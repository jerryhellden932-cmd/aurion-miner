#!/usr/bin/env python3
"""Snapshot and replay the native SQLite ledger; never restore signing state."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COIN_SOURCE = ROOT / "coin/aurion.py"
if not COIN_SOURCE.is_file():
    COIN_SOURCE = Path(__file__).resolve().parent / "aurion.py"


def load_coin(source=COIN_SOURCE):
    spec = importlib.util.spec_from_file_location("aurion_backup", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


coin = load_coin()
SCHEMA = {
    "txs": [("id", "TEXT", 0, 1), ("j", "TEXT", 0, 0)],
    "cps": [("hash", "TEXT", 0, 1), ("j", "TEXT", 0, 0)],
    "metadata": [("key", "TEXT", 0, 1), ("value", "TEXT", 1, 0)],
}


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as data:
        for chunk in iter(lambda: data.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def private_copy(source, destination):
    """Exclusive, bounded-memory copy; never replace an existing destination."""
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output, open(source, "rb") as data:
        for chunk in iter(lambda: data.read(1024 * 1024), b""):
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON field")
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON value")))


def standalone(path):
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_file():
        raise ValueError("a regular existing SQLite backup is required")
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-journal", "-shm")):
        raise ValueError("use a standalone SQLite backup, not an active database with sidecars")
    return path


def validate_database(path, params, module=coin):
    """Reject absent schema before Node could initialize an empty replacement."""
    path = standalone(path)
    with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("ledger database integrity check failed")
        objects = db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if sorted(objects) != sorted(("table", name) for name in SCHEMA):
            raise ValueError("unsupported or missing native ledger schema")
        for table, expected in SCHEMA.items():
            columns = [(r[1], r[2].upper(), r[3], r[5]) for r in db.execute(f"PRAGMA table_info({table})")]
            if columns != expected:
                raise ValueError("unsupported native ledger table " + table)
        metadata = db.execute("SELECT key,value FROM metadata ORDER BY key").fetchall()
        genesis = module.cp_hash(module.genesis_checkpoint(params))
        if metadata != [("genesis", genesis)]:
            raise ValueError("stored metadata/genesis differs from the configured native network")
        rows = {}
        for table, key in (("txs", "id"), ("cps", "hash")):
            records = []
            if db.execute(f"SELECT 1 FROM {table} WHERE length(CAST(j AS BLOB)) > 16000000 LIMIT 1").fetchone():
                raise ValueError("oversized persisted ledger row")
            for ident, text in db.execute(f"SELECT {key},j FROM {table} ORDER BY rowid"):
                if not isinstance(ident, str) or not module.HEX64_RE.fullmatch(ident) or not isinstance(text, str):
                    raise ValueError("invalid persisted ledger row")
                # The native transport bounds objects; reject oversized rows before decoding.
                if len(text.encode("utf-8")) > 16_000_000:
                    raise ValueError("oversized persisted ledger row")
                obj = strict_json(text)
                try:
                    actual = module.tx_id(obj) if table == "txs" else module.cp_hash(obj)
                except (KeyError, TypeError, ValueError) as error:
                    raise ValueError("malformed persisted ledger object") from error
                if actual != ident:
                    raise ValueError("persisted ledger body hash mismatch")
                records.append((ident, obj))
            if len({r[0] for r in records}) != len(records):
                raise ValueError("duplicate persisted ledger identifier")
            rows[table] = records
        return {"metadata": metadata, "rows": rows}


def sqlite_snapshot(source, destination):
    """SQLite backup API includes committed WAL pages; source connection is read-only."""
    source, destination = Path(source).absolute(), Path(destination).absolute()
    if source.is_symlink() or not source.is_file():
        raise ValueError("source must be a regular existing file")
    if any(Path(str(destination) + suffix).exists() or Path(str(destination) + suffix).is_symlink()
           for suffix in ("-wal", "-journal", "-shm")):
        raise ValueError("backup destination has preexisting SQLite sidecars")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    try:
        with contextlib.closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src:
            with contextlib.closing(sqlite3.connect(destination)) as dst:
                src.backup(dst)
        # Windows FlushFileBuffers requires a handle opened for writing.
        with open(destination, "r+b") as output:
            os.fsync(output.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def verify(source, params):
    validated = validate_database(source, params)
    with tempfile.TemporaryDirectory(prefix="aurion-restore-test-") as tmp:
        copy = Path(tmp) / (params.name + ".db")
        private_copy(source, copy)
        node = coin.Node.__new__(coin.Node)
        try:
            coin.Node.__init__(node, params, tmp, log=lambda *_: None)
            if set(node.txs) != {r[0] for r in validated["rows"]["txs"]} or set(node.cps) != {r[0] for r in validated["rows"]["cps"]} | {node.genesis_hash}:
                raise ValueError("native replay omitted persisted history")
            return node.info()
        finally:
            if getattr(node, "db", None) is not None:
                node.db.close()


def backup(source, destination, params):
    source, destination = Path(source).absolute(), Path(destination).absolute()
    manifest = destination.with_suffix(destination.suffix + ".manifest.json")
    if destination.exists() or destination.is_symlink() or manifest.exists() or manifest.is_symlink():
        raise ValueError("backup and manifest destinations must both be new")
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        sqlite_snapshot(source, destination)
        created = True
        info = verify(destination, params)
        report = {"schema": 1, "network": info["network"], "genesis": info["genesis"],
                  "height": info["height"], "best": info["best"], "sha256": sha256(destination),
                  "wallets_included": False, "replay_verified": True, "security_certified": False}
        private_write(manifest, (json.dumps(report, indent=2) + "\n").encode())
        return report
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--network", choices=["mainnet", "testnet", "regtest"], required=True)
    parser.add_argument("--founder", help="testnet/regtest genesis only")
    parser.add_argument("--allow-unaudited-mainnet", action="store_true")
    args = parser.parse_args()
    params = coin.make_params(args.network, args.founder, args.allow_unaudited_mainnet)
    if args.verify_only:
        result = verify(args.source, params)
    elif args.destination:
        result = backup(args.source, args.destination, params)
    else:
        parser.error("destination or --verify-only is required")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
