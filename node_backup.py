#!/usr/bin/env python3
"""Create and independently replay a SQLite node backup without touching wallets."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COIN_SOURCE = ROOT / "coin/aurion.py"
if not COIN_SOURCE.is_file():
    COIN_SOURCE = Path(__file__).resolve().parent / "aurion.py"
spec = importlib.util.spec_from_file_location("aurion_backup", COIN_SOURCE)
coin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coin)


def verify(source, params):
    with tempfile.TemporaryDirectory(prefix="aurion-restore-test-") as tmp:
        copy = Path(tmp) / (params.name + ".db")
        shutil.copyfile(source, copy)
        node = coin.Node(params, tmp, log=lambda *_: None)
        try:
            return node.info()
        finally:
            node.db.close()


def backup(source, destination, params):
    source, destination = Path(source).resolve(), Path(destination).absolute()
    if not source.is_file() or destination.exists() or destination.is_symlink():
        raise ValueError("source must exist and destination must be new")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        src = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
        try:
            dst = sqlite3.connect(destination)
            try:
                src.backup(dst)
            finally:
                dst.close()
        finally:
            src.close()
        info = verify(destination, params)
        digest = hashlib.sha256()
        with open(destination, "rb") as data:
            for chunk in iter(lambda: data.read(1024 * 1024), b""):
                digest.update(chunk)
        report = {"schema": 1, "network": info["network"], "genesis": info["genesis"],
                  "height": info["height"], "best": info["best"],
                  "sha256": digest.hexdigest(),
                  "wallets_included": False, "replay_verified": True}
        manifest = destination.with_suffix(destination.suffix + ".manifest.json")
        with open(manifest, "x") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
        return report
    except BaseException:
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
