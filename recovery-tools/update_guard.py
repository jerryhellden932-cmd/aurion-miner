#!/usr/bin/env python3
"""Offline native-node upgrade rehearsal. Never install, start, restore or sign."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

HELPER = Path(__file__).with_name("node_backup.py")
spec = importlib.util.spec_from_file_location("node_backup_guard", HELPER)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)
STATE_FIELDS = ("height", "time", "hash", "challenge", "leaf", "dist", "weight", "balances", "last_idx", "plots", "htlcs", "processed", "receipts", "minted")


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def restrict_replay(folder):
    """Defence against accidental writes/network use, not a hostile-code sandbox."""
    root = Path(folder).resolve()
    def inside(path):
        if isinstance(path, int):
            return
        target = Path(os.fsdecode(path)).resolve()
        if target != root and root not in target.parents:
            raise PermissionError("rehearsal attempted a write outside its isolated directory")
    def audit(event, args):
        if event.startswith("socket.") or event in ("subprocess.Popen", "os.system", "os.fork", "os.posix_spawn"):
            raise PermissionError("network/process creation is disabled during offline replay")
        if event == "open":
            path, mode, flags = args
            if (mode and any(c in mode for c in "wa+")) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
                inside(path)
        elif event == "sqlite3.connect" and args[0] != ":memory:":
            # Native Node uses a regular filename; URI database paths are not allowed here.
            if str(args[0]).startswith("file:"):
                raise PermissionError("URI database connections are disabled in candidate replay")
            inside(args[0])
        elif event in ("os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.truncate"):
            inside(args[0])
        elif event in ("os.rename", "os.link", "os.symlink"):
            inside(args[0]); inside(args[1])
    sys.addaudithook(audit)


def worker(request_file, response_file):
    request = backup.strict_json(Path(request_file).read_bytes())
    folder = Path(request["folder"])
    os.chdir(folder)
    restrict_replay(folder)
    coin = backup.load_coin(folder / "aurion.py")
    params = coin.make_params(request["network"], request["founder"], request["allow_mainnet"])
    if params.name != "aurion-" + request["network"]:
        raise ValueError("candidate changed native network identity")
    database = folder / (params.name + ".db")
    # Validation uses the known helper before the audit hook restricts SQLite URI
    # reads, so here inspect a read-only copy via a regular file connection.
    node = coin.Node.__new__(coin.Node)
    try:
        coin.Node.__init__(node, params, str(folder), log=lambda *_: None)
        snapshot = {"profile": "aurion-native-replay-v1", "network": params.name,
                    "params": vars(params), "genesis": node.genesis_hash, "best": node.best,
                    "main": list(node.main), "txs": node.txs, "cps": node.cps,
                    "tips": sorted(node.tips), "children": node.children,
                    "states": {key: {field: getattr(state, field) for field in STATE_FIELDS}
                               for key, state in node.states.items()}}
        if set(node.txs) != set(request["tx_ids"]) or set(node.cps) != set(request["cp_ids"]) | {node.genesis_hash}:
            raise ValueError("replay omitted persisted transaction/checkpoint history")
        backup.private_write(response_file, encoded({"version": coin.VERSION, "snapshot": snapshot}))
    finally:
        if getattr(node, "db", None) is not None:
            node.db.close()
    # Node may alter only its scratch copy; persisted journals must still match.
    with contextlib.closing(sqlite3.connect(database)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("replay corrupted its ledger copy")
        objects = db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if sorted(objects) != sorted(("table", name) for name in backup.SCHEMA):
            raise ValueError("replay changed the supported native ledger schema")
        for table, expected in backup.SCHEMA.items():
            columns = [(r[1], r[2].upper(), r[3], r[5]) for r in db.execute(f"PRAGMA table_info({table})")]
            if columns != expected:
                raise ValueError("replay changed native ledger columns")
        if db.execute("SELECT key,value FROM metadata ORDER BY key").fetchall() != [tuple(r) for r in request["metadata"]]:
            raise ValueError("replay rewrote metadata")
        for table, key in (("txs", "id"), ("cps", "hash")):
            rows = [(ident, backup.strict_json(text)) for ident, text in db.execute(f"SELECT {key},j FROM {table} ORDER BY rowid")]
            if digest(rows) != request[table + "_digest"]:
                raise ValueError("replay rewrote persisted history")


def replay(source, ledger, validated, network, founder, allow_mainnet, timeout, destination):
    with tempfile.TemporaryDirectory(prefix="aurion-upgrade-replay-") as temporary:
        folder = Path(temporary)
        backup.private_copy(source, folder / "aurion.py")
        backup.private_copy(ledger, folder / ("aurion-" + network + ".db"))
        request = {"folder": str(folder), "network": network, "founder": founder, "allow_mainnet": allow_mainnet,
                   "tx_ids": [r[0] for r in validated["rows"]["txs"]], "cp_ids": [r[0] for r in validated["rows"]["cps"]],
                   "metadata": validated["metadata"], "txs_digest": digest(validated["rows"]["txs"]),
                   "cps_digest": digest(validated["rows"]["cps"])}
        backup.private_write(folder / "request.json", encoded(request))
        log = folder / "replay.log"
        with open(log, "xb") as output:
            completed = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--_worker", str(folder / "request.json"), str(folder / "result.json")],
                                       cwd=folder, stdout=output, stderr=output, timeout=timeout)
        if completed.returncode:
            # Replay logs contain public ledger data only; no wallet is passed to a worker.
            detail = log.read_bytes()[-4000:].decode("utf-8", "replace")
            raise ValueError("isolated replay failed: " + detail)
        result = backup.strict_json((folder / "result.json").read_bytes())
        backup.private_write(destination, encoded(result))
        return result


def wallet_json(path, coin):
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("wallet must be a regular bounded native JSON file")
    raw = path.read_bytes(); data = backup.strict_json(raw)
    if not isinstance(data, dict) or data.get("type") != "aurion-wallet" or type(data.get("v")) is not int or data["v"] != 1:
        raise ValueError("unsupported native wallet profile")
    height, counter = data.get("height"), data.get("next_index")
    if type(height) is not int or not 1 <= height <= 20 or type(counter) is not int or not 0 <= counter <= 1 << height:
        raise ValueError("invalid wallet height/signing floor")
    def hex_value(value, length):
        return isinstance(value, str) and len(value) == length * 2 and all(c in "0123456789abcdef" for c in value)
    if not hex_value(data.get("pub_seed"), 32) or not isinstance(data.get("leaves"), list) or len(data["leaves"]) != 1 << height or any(not hex_value(v, 32) for v in data["leaves"]):
        raise ValueError("invalid wallet public identity")
    if ("seed" in data) == ("enc" in data):
        raise ValueError("wallet must contain exactly one native seed representation")
    if set(data) != {"type", "v", "height", "address", "pub_seed", "leaves", "next_index", "enc" if "enc" in data else "seed"}:
        raise ValueError("unsupported native wallet fields")
    if "seed" in data and not hex_value(data["seed"], 32):
        raise ValueError("invalid plaintext seed representation")
    if "enc" in data:
        enc = data["enc"]
        if not isinstance(enc, dict) or set(enc) != {"salt", "nonce", "ct", "tag"} or any(not hex_value(enc[k], size) for k, size in (("salt", 16), ("nonce", 16), ("ct", 32), ("tag", 32))):
            raise ValueError("invalid encrypted seed representation")
    key = coin.MerkleKey(b"\0" * 32, bytes.fromhex(data["pub_seed"]), height, leaves=[bytes.fromhex(v) for v in data["leaves"]])
    if key.address != data.get("address"):
        raise ValueError("wallet public address/root mismatch")
    return raw, data


def signing_floor(path, address, capacity):
    path = backup.standalone(path)
    with contextlib.closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("corrupt signing journal")
        tables = db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if tables != [("table", "signing")]:
            raise ValueError("unsupported signing journal schema")
        cols = [(r[1], r[2].upper(), r[3], r[5]) for r in db.execute("PRAGMA table_info(signing)")]
        if cols != [("address", "TEXT", 0, 1), ("next_index", "INTEGER", 1, 0)]:
            raise ValueError("unsupported signing journal columns")
        rows = db.execute("SELECT address,next_index FROM signing").fetchall()
        if len(rows) != 1 or rows[0][0] != address or type(rows[0][1]) is not int or not 0 <= rows[0][1] <= capacity:
            raise ValueError("signing journal must contain the matching wallet's bounded floor")
        return rows[0][1]


def wallet_bundle(paths, folder, coin, snapshot, stopped):
    if not paths:
        return []
    if not stopped:
        raise ValueError("wallet bundles require --signers-stopped: stop all signers, miners and aliases throughout capture")
    folder.mkdir(mode=0o700)
    records, unchanged, absent_guards = [], [], []
    for index, original in enumerate(paths):
        original = Path(original).absolute()
        target = folder / str(index); target.mkdir(mode=0o700)
        raw, data = wallet_json(original, coin)
        journal = Path(str(original) + ".signing.sqlite")
        # Refuse an absent sidecar: a zero JSON counter can itself be a rollback.
        before = (backup.sha256(original), backup.sha256(backup.standalone(journal)))
        if before[0] != hashlib.sha256(raw).hexdigest():
            raise ValueError("wallet changed before capture; keep every signer stopped")
        backup.private_write(target / "wallet.json", raw)
        backup.sqlite_snapshot(journal, target / "wallet.json.signing.sqlite")
        sql_floor = signing_floor(target / "wallet.json.signing.sqlite", data["address"], 1 << data["height"])
        guard = original.parent / (".aurion-signing-" + data["address"] + ".json")
        guard_floor = 0
        if guard.exists() or guard.is_symlink():
            if guard.is_symlink() or guard.stat().st_size > 4096:
                raise ValueError("invalid shared signing guard")
            guard_raw = guard.read_bytes(); value = backup.strict_json(guard_raw)
            if not isinstance(value, dict) or set(value) != {"v", "address", "height", "next_index", "generation"} or value["v"] != 1 or type(value["v"]) is not int or value["address"] != data["address"] or type(value["height"]) is not int or value["height"] != data["height"] or type(value["next_index"]) is not int or not 0 <= value["next_index"] <= 1 << data["height"] or type(value["generation"]) is not int or value["generation"] < 0:
                raise ValueError("shared signing guard identity/floor is invalid")
            backup.private_write(target / guard.name, guard_raw); guard_floor = value["next_index"]
            if guard.read_bytes() != guard_raw:
                raise ValueError("shared signing guard changed while capturing")
            unchanged.append((guard, hashlib.sha256(guard_raw).hexdigest()))
        else:
            absent_guards.append(guard)
        if before != (backup.sha256(original), backup.sha256(journal)):
            raise ValueError("wallet/signing journal changed while capturing; keep every signer stopped")
        unchanged.extend(((original, before[0]), (journal, before[1])))
        floor = max(data["next_index"], sql_floor)
        # The active 0.2.1 Wallet reads only JSON and its per-file SQL journal.
        # Retaining a newer guard does not make that older binary enforce it.
        if guard_floor > floor:
            raise ValueError("shared guard exceeds the active JSON/journal floor; this native profile cannot safely resume it")
        exposed = [tx["body"]["idx"] for tx in snapshot["txs"].values() if tx["body"]["from"] == data["address"]]
        exposed += [cp["body"]["idx"] for cp in snapshot["cps"].values() if cp["body"].get("producer") == data["address"]]
        known = max(exposed, default=-1) + 1
        if floor < known:
            raise ValueError("wallet/journal floor is below a signature already present in retained ledger history")
        records.append({"address": data["address"], "height": data["height"], "json_floor": data["next_index"],
                        "journal_floor": sql_floor, "shared_guard_floor": guard_floor, "preserved_floor": floor,
                        "known_ledger_floor": known, "path": str(target.relative_to(folder.parent)), "encrypted": "enc" in data,
                        "encrypted_seed_decrypted": False})
    for record in records:
        if record["preserved_floor"] < max(r["preserved_floor"] for r in records if r["address"] == record["address"]):
            raise ValueError("a supplied alias has an older signing floor; do not restore or resume it")
    if any(backup.sha256(path) != expected for path, expected in unchanged):
        raise ValueError("wallet bundle changed during capture; keep every signer stopped")
    for original in paths:
        backup.standalone(str(Path(original).absolute()) + ".signing.sqlite")
    if any(path.exists() or path.is_symlink() for path in absent_guards):
        raise ValueError("shared signing guard appeared during capture; keep every signer stopped")
    return records


def preflight(source, output, current_source, candidate_source, network, founder=None, allow_mainnet=False,
              expected_best=None, expected_height=None, wallets=(), signers_stopped=False, timeout=120):
    source = backup.standalone(source); output = Path(output).absolute()
    current_source, candidate_source = Path(current_source).absolute(), Path(candidate_source).absolute()
    if network not in ("mainnet", "testnet", "regtest") or type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("invalid network or replay timeout")
    if (expected_best is None) != (expected_height is None):
        raise ValueError("expected-best and expected-height must be supplied together")
    if expected_best is not None and (not isinstance(expected_best, str) or not backup.coin.HEX64_RE.fullmatch(expected_best) or type(expected_height) is not int or expected_height < 0):
        raise ValueError("invalid trusted source checkpoint")
    protected = [source.parent.resolve(), *(Path(w).absolute().parent.resolve() for w in wallets)]
    resolved_output = output.resolve()
    if any(resolved_output == p or p in resolved_output.parents for p in protected):
        raise ValueError("rehearsal output must be outside the original database/wallet directories")
    if output.exists() or output.is_symlink():
        raise ValueError("rehearsal output must be a new directory; nothing will be overwritten")
    for code in (current_source, candidate_source):
        if code.is_symlink() or not code.is_file():
            raise ValueError("both trusted reviewed native source files must exist")
    if wallets and not signers_stopped:
        raise ValueError("wallet bundle requires explicit --signers-stopped acknowledgement")
    original_hash = backup.sha256(source)
    code_hashes = {label: backup.sha256(code) for label, code in (("current", current_source), ("candidate", candidate_source))}
    # The bundled reviewed 0.2.1 profile validates the source envelope/schema.
    # Both explicitly supplied code artifacts execute only in replay workers.
    baseline_coin = backup.coin
    params = baseline_coin.make_params(network, founder, allow_mainnet)
    validated = backup.validate_database(source, params, baseline_coin)
    output.mkdir(mode=0o700)
    try:
        backup.private_copy(source, output / "ledger.db")
        for label, code in (("current", current_source), ("candidate", candidate_source)):
            backup.private_copy(code, output / (label + "-aurion.py"))
        current = replay(output / "current-aurion.py", output / "ledger.db", validated, network, founder, allow_mainnet, timeout, output / "current-state.json")
        candidate = replay(output / "candidate-aurion.py", output / "ledger.db", validated, network, founder, allow_mainnet, timeout, output / "candidate-state.json")
        state = current["snapshot"]; best = state["states"][state["best"]]
        if expected_best is not None and (state["best"] != expected_best or best["height"] != expected_height):
            raise ValueError("backup does not match the operator's trusted source checkpoint")
        if state != candidate["snapshot"]:
            changed = [key for key in state if state[key] != candidate["snapshot"].get(key)]
            raise ValueError("candidate recovered different canonical state/history: " + ", ".join(changed))
        bundles = wallet_bundle(wallets, output / "wallets", baseline_coin, state, signers_stopped)
        if backup.sha256(source) != original_hash or backup.sha256(output / "ledger.db") != original_hash:
            raise ValueError("immutable source backup changed during rehearsal")
        for label, code in (("current", current_source), ("candidate", candidate_source)):
            if backup.sha256(code) != code_hashes[label] or backup.sha256(output / (label + "-aurion.py")) != code_hashes[label]:
                raise ValueError("reviewed source artifact changed during rehearsal")
        files = {str(p.relative_to(output)): backup.sha256(p) for p in sorted(output.rglob("*")) if p.is_file()}
        report = {"schema": 1, "compatible": True, "replay_equal": True, "network": state["network"], "genesis": state["genesis"],
                  "height": best["height"], "best": state["best"], "minted": best["minted"], "registered_plots": len(best["plots"]),
                  "current_version": current["version"], "candidate_version": candidate["version"], "state_sha256": digest(state),
                  "source_checkpoint_operator_pinned": expected_best is not None, "wallets": bundles, "sha256": files,
                  "production_directory_written": False, "installation_performed": False, "network_used": False,
                  "security_certified": False, "whole_backup_rollback_protection": "operator-provided exact checkpoint" if expected_best is not None else "none",
                  "plot_files_included": False, "original_plot_and_signing_directories_must_be_retained": True,
                  "wallet_capture_requires_all_signers_stopped": True, "crash_atomic_wallet_profile_guaranteed": False,
                  "candidate_code_requires_operator_review": True, "windows_acls_verified": False}
        backup.private_write(output / "report.json", encoded(report))
        backup.private_write(output / "SHA256SUMS.txt", ("".join(f"{value}  {name}\n" for name, value in {**files, "report.json": backup.sha256(output / "report.json")}.items())).encode())
        return report
    except BaseException as error:
        try:
            backup.private_write(output / "FAILED.json", encoded({"compatible": False, "error": str(error), "installation_performed": False}))
        except OSError:
            pass
        raise


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--_worker":
        worker(sys.argv[2], sys.argv[3]); return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="standalone consistent SQLite backup, never a live WAL database")
    parser.add_argument("output", type=Path, help="new private rehearsal directory outside original data folders")
    parser.add_argument("--network", choices=["mainnet", "testnet", "regtest"], required=True)
    parser.add_argument("--current-source", type=Path, required=True, help="reviewed currently running aurion.py")
    parser.add_argument("--candidate-source", type=Path, required=True, help="reviewed compatible candidate aurion.py; not arbitrary untrusted code")
    parser.add_argument("--founder")
    parser.add_argument("--allow-unaudited-mainnet", action="store_true")
    parser.add_argument("--expected-best")
    parser.add_argument("--expected-height", type=int)
    parser.add_argument("--wallet", type=Path, action="append", default=[], help="stopped native wallet or plot key JSON; include every alias")
    parser.add_argument("--signers-stopped", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        result = preflight(args.source, args.output, args.current_source, args.candidate_source, args.network, args.founder,
                           args.allow_unaudited_mainnet, args.expected_best, args.expected_height, args.wallet, args.signers_stopped, args.timeout)
    except (ValueError, OSError, sqlite3.Error, subprocess.TimeoutExpired) as error:
        parser.exit(1, "Upgrade refused: " + str(error) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
