"""Offline, source-pinned v1 preservation evidence; never import or activate it.

Only the SELECT-only hosted public-ledger backup format is supported. The caller
must separately retain and supply the ledger/source hashes, genesis and selected
checkpoint. A packet is checked by replaying that ledger again, not by trusting
its own hashes. Reviewed Python source is executed: a hash pin is not a sandbox.
Inputs must reside in a stable local directory without concurrent writers.
Private wallets, unbroadcast signatures, physical plots and hosted account/market
records are outside this evidence. This does not define a v1-to-v3 ownership claim.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

MAX_LEDGER_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_PACKET_BYTES = 64 * 1024 * 1024
MAX_OBJECT_BYTES = 256 * 1024
MAX_OBJECTS = 2048
MAX_STATE_ENTRIES = 250_000
HEX = re.compile(r"[0-9a-f]{64}")
STATE_FIELDS = ("height", "time", "hash", "challenge", "leaf", "dist", "weight",
                "balances", "last_idx", "plots", "htlcs", "processed", "receipts", "minted")
SAFETY = {"real_funds_ready": False, "security_certification": False,
          "migration_imported": False, "activation_authorized": False,
          "private_signing_state_verified": False, "physical_plot_files_verified": False}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("invalid bounded JSON") from exc


def path_without_symlinks(value):
    path = Path(os.path.abspath(os.fspath(value)))
    if path.resolve() != path:
        raise ValueError("symlink paths are unsupported")
    return path


def read_bounded(value, maximum):
    path = path_without_symlinks(value)
    # Opening a FIFO must not wait for another process before fstat rejects it.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError("input must be a bounded regular file")
        raw = source.read(maximum + 1)
        if not 0 < len(raw) <= maximum or len(raw) != info.st_size:
            raise ValueError("input size changed or exceeds bound")
    return path, raw


def require_hash(value, label):
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        raise ValueError("invalid separate " + label + " pin")
    return value


def fields(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("unknown or missing " + label + " fields")


def unsigned(value):
    return type(value) is int and 0 <= value < 2 ** 63


def table(value, columns, label):
    fields(value, ("columns", "rows", "meta"), label)
    if value["columns"] != columns or not isinstance(value["rows"], list):
        raise ValueError("invalid " + label + " table")
    fields(value["meta"], ("rows_read", "rows_written"), label + " SQL metadata")
    if (not unsigned(value["meta"]["rows_read"]) or
            type(value["meta"]["rows_written"]) is not int or value["meta"]["rows_written"] != 0):
        raise ValueError("backup must describe SELECT-only queries")


def ledger_shape(data, genesis, network):
    fields(data, ("schema_version", "kind", "captured_at", "namespace_id", "object_name",
                  "metadata", "objects", "counts", "secret_values_included",
                  "account_records_included", "restore_performed"), "ledger")
    if (type(data["schema_version"]) is not int or data["schema_version"] != 1 or
            data["kind"] != "aurion-hosted-public-ledger-backup"):
        raise ValueError("unsupported ledger backup format")
    for key in ("secret_values_included", "account_records_included", "restore_performed"):
        if data[key] is not False:
            raise ValueError("unsupported private/restored backup")
    if (not isinstance(data["namespace_id"], str) or
            re.fullmatch(r"[0-9a-f]{32}", data["namespace_id"]) is None or
            data["object_name"] != "aurion-" + network + "-v1"):
        raise ValueError("unsupported hosted object identity")
    captured = data["captured_at"]
    if not isinstance(captured, str) or len(captured) > 40:
        raise ValueError("invalid capture time")
    try:
        parsed = datetime.datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid capture time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError("capture time must specify UTC")
    table(data["metadata"], ["key", "value"], "metadata")
    if data["metadata"]["rows"] != [["genesis", genesis]]:
        raise ValueError("ledger metadata does not match separate genesis pin")
    table(data["objects"], ["seq", "kind", "hash", "body"], "objects")
    table(data["counts"], ["count", "highest_seq"], "counts")
    rows = data["objects"]["rows"]
    if len(rows) > MAX_OBJECTS:
        raise ValueError("too many ledger objects for bounded offline replay")
    previous, seen = 0, set()
    objects = []
    for row in rows:
        if not isinstance(row, list) or len(row) != 4:
            raise ValueError("invalid object row")
        seq, kind, ident, body = row
        if not unsigned(seq) or seq <= previous or kind not in ("tx", "cp"):
            raise ValueError("invalid object sequence or type")
        require_hash(ident, "object hash")
        if ident in seen:
            raise ValueError("duplicate ledger object hash")
        if not isinstance(body, str) or not 0 < len(body.encode("utf-8")) <= MAX_OBJECT_BYTES:
            raise ValueError("invalid or oversized object body")
        obj = strict_json(body)
        fields(obj, ("body", "sig"), "signed object")
        if not isinstance(obj["body"], dict) or not isinstance(obj["sig"], str):
            raise ValueError("invalid signed object")
        objects.append((seq, kind, ident, obj))
        previous = seq
        seen.add(ident)
    count_rows = data["counts"]["rows"]
    if (not isinstance(count_rows, list) or len(count_rows) != 1 or
            not isinstance(count_rows[0], list) or len(count_rows[0]) != 2 or
            not all(unsigned(v) for v in count_rows[0]) or count_rows != [[len(rows), previous]]):
        raise ValueError("object count/sequence differs from backup inventory")
    return objects


def accounting(coin, params, state):
    balances, escrows = state["balances"], state["htlcs"]
    if not all(unsigned(v) for v in balances.values()) or not unsigned(state["minted"]):
        raise ValueError("invalid balance or issuance")
    open_units = 0
    for value in escrows.values():
        if value["state"] not in ("open", "claimed", "refunded") or not unsigned(value["amount"]):
            raise ValueError("invalid preserved escrow state")
        if value["state"] == "open":
            open_units += value["amount"]
    initial = coin.FOUNDER_ALLOCATION if params.founder else 0
    minted = state["minted"]
    if minted > coin.MINING_SUPPLY or sum(balances.values()) + open_units != initial + minted:
        raise ValueError("issuance conservation failed")
    locks = {addr: {"balance_units": balance,
                    "locked_at_checkpoint_units": params.locked(addr, state["height"]),
                    "spendable_at_checkpoint_units": balance - params.locked(addr, state["height"]),
                    "locked_at_next_checkpoint_units": params.locked(addr, state["height"] + 1),
                    "spendable_at_next_checkpoint_units": balance - params.locked(addr, state["height"] + 1)}
             for addr, balance in balances.items()}
    if any(value["spendable_at_checkpoint_units"] < 0 for value in locks.values()):
        raise ValueError("founder vesting exceeds preserved balance")
    return {"initial_allocation_units": initial, "mined_units": minted,
            "balance_units": sum(balances.values()), "open_escrow_units": open_units,
            "issued_units": initial + minted, "supply_conserved": True,
            "vesting": locks}


def compile_packet(ledger, coin_source, *, network, genesis, checkpoint,
                   ledger_sha256, coin_sha256, founder=None):
    """Re-derive preservation evidence; pins are caller inputs, never ledger fields."""
    if network not in ("mainnet", "testnet", "regtest") or (network == "mainnet" and founder is not None):
        raise ValueError("invalid network/founder override")
    for value, label in ((genesis, "genesis"), (checkpoint, "checkpoint"),
                         (ledger_sha256, "ledger SHA256"), (coin_sha256, "source SHA256")):
        require_hash(value, label)
    ledger_path, raw = read_bounded(ledger, MAX_LEDGER_BYTES)
    source_path, source = read_bounded(coin_source, MAX_SOURCE_BYTES)
    if hashlib.sha256(raw).hexdigest() != ledger_sha256 or hashlib.sha256(source).hexdigest() != coin_sha256:
        raise ValueError("input differs from separate source/ledger hash pins")
    data = strict_json(raw)
    objects = ledger_shape(data, genesis, network)
    coin = types.ModuleType("aurion_preservation_replay")
    coin.__file__ = str(source_path)
    exec(compile(source, str(source_path), "exec"), coin.__dict__)
    params = coin.make_params(network, founder, allow_unaudited_mainnet=True)
    node = coin.Node(params, datadir=None, log=lambda *_: None)
    if node.p.name != "aurion-" + network or node.genesis_hash != genesis:
        raise ValueError("source/configured genesis differs from separate genesis pin")
    if tuple(coin.State.__slots__) != STATE_FIELDS:
        raise ValueError("unsupported v1 state fields")
    states, totals, exposure = {}, {}, {}
    state_entries = 0

    def capture(ident):
        nonlocal state_entries
        st = node.states[ident]
        state = strict_json(encoded({field: getattr(st, field) for field in STATE_FIELDS}))
        state_entries += sum(len(state[field]) for field in
                             ("balances", "last_idx", "plots", "htlcs", "processed", "receipts"))
        if state_entries > MAX_STATE_ENTRIES:
            raise ValueError("checkpoint-state inventory exceeds bounded replay budget")
        totals[ident] = accounting(coin, params, state)
        states[ident] = state

    capture(genesis)
    tx_ids, cp_ids = set(), {genesis}
    for _, kind, ident, obj in objects:
        expected = coin.tx_id(obj) if kind == "tx" else coin.cp_hash(obj)
        if expected != ident:
            raise ValueError("stored object hash/body mismatch")
        status, value = (node.add_tx if kind == "tx" else node.add_checkpoint)(obj, relaxed=True, persist=False)
        if status != "ok" or value != ident:
            raise ValueError("v1 object replay failed: " + str(status))
        body = obj["body"]
        address = body["from"] if kind == "tx" else body["producer"]
        entries = exposure.setdefault(address, {})
        entries.setdefault(body["idx"], []).append({"kind": kind, "hash": ident})
        if kind == "tx":
            tx_ids.add(ident)
        else:
            cp_ids.add(ident)
            capture(ident)
    if set(node.txs) != tx_ids or set(node.cps) != cp_ids or set(states) != cp_ids:
        raise ValueError("replay did not preserve all accepted history")
    if node.best != checkpoint:
        raise ValueError("replayed selected checkpoint differs from separate checkpoint pin")
    signing = {address: {"maximum_exposed_index": max(indices),
                         "minimum_next_index_from_public_history": max(indices) + 1,
                         "observed_signatures": [{"index": index, "objects": entries}
                                                 for index, entries in sorted(indices.items())],
                         "reused_indices": sorted(index for index, entries in indices.items() if len(entries) > 1)}
               for address, indices in exposure.items()}
    replay = {"params": vars(params), "genesis": genesis, "best": node.best,
              "height": node.height(), "main": list(node.main), "txs": node.txs,
              "cps": node.cps, "tips": sorted(node.tips), "children": node.children,
              "states": states, "currently_retained_states": sorted(node.states)}
    packet = {"schema_version": 1, "kind": "aurion-offline-v1-preservation",
              "scope": "hosted-public-ledger-only; no ownership migration or production import",
              "pins": {"network": network, "genesis": genesis, "checkpoint": checkpoint,
                       "ledger_sha256": ledger_sha256, "coin_sha256": coin_sha256},
              "source_version": coin.VERSION, "history": data, "replay": replay,
              "accounting": totals, "signing_exposure": signing,
              "limitations": ["Caller supplies independently retained pins; pins do not certify security.",
                              "Reviewed source is executed without a hostile-code sandbox.",
                              "Private journals and unbroadcast signatures may require higher signing floors.",
                              "Physical plots and private hosted account/market storage are not inspected.",
                              "The selected checkpoint has no new finality guarantee.",
                              "This packet defines no legacy-to-ML-DSA ownership claims or activation."],
              **SAFETY}
    packet["commitments"] = {"history_sha256": digest(data), "replay_sha256": digest(replay),
                             "accounting_sha256": digest(totals), "signing_exposure_sha256": digest(signing)}
    packet["packet_sha256"] = digest(packet)
    if len(encoded(packet)) > MAX_PACKET_BYTES:
        raise ValueError("preservation packet exceeds output bound")
    # Captured byte snapshots are used throughout; detect ordinary concurrent drift.
    if (read_bounded(ledger_path, MAX_LEDGER_BYTES)[1] != raw or
            read_bounded(source_path, MAX_SOURCE_BYTES)[1] != source):
        raise ValueError("input changed during replay")
    return packet


def verify_candidate(candidate, packet):
    """Exact rederivation rejects self-rehashed, incomplete or substituted packets."""
    _, raw = read_bounded(candidate, MAX_PACKET_BYTES)
    parsed = strict_json(raw)
    if encoded(parsed) != encoded(packet):
        raise ValueError("candidate differs from source-pinned rederived preservation packet")
    return {"schema_version": 1, "kind": "aurion-offline-v1-preservation-verification",
            "candidate_rederived_equal": True, "packet_sha256": packet["packet_sha256"],
            "pins": packet["pins"], "height": packet["replay"]["height"], **SAFETY}


def write_exclusive(output, value, inputs=()):
    path = path_without_symlinks(output)
    if path in {path_without_symlinks(item) for item in inputs}:
        raise ValueError("output must differ from every input")
    raw = encoded(value)
    if len(raw) > MAX_PACKET_BYTES:
        raise ValueError("output exceeds packet bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as destination:
        destination.write(raw)
        destination.flush()
        os.fsync(destination.fileno())
    return path
