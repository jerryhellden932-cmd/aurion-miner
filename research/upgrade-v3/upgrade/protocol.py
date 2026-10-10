"""Isolated ML-DSA-65 account/rotation candidate. NOT a mainnet consensus node.

The standard algorithm is provided by cryptography/OpenSSL, never reimplemented.
This local harness deliberately cannot accept the aurion-mainnet chain ID.
It has no network, mining, bridge or mainnet wallet import/export interface.
"""
import hashlib
import json
import re
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey

CONTEXT = b"Aurion/upgrade-devnet/v3/command"
ROTATION_CONTEXT = b"Aurion/upgrade-devnet/v3/new-key"
ACCOUNT_RE = re.compile(r"^aur3[0-9a-f]{64}$")
PUBLIC_KEY_BYTES = 1952
SIGNATURE_BYTES = 3309
MAX_UNITS = 21_000_000 * 100_000_000
MAX_ENVELOPE_BYTES = 32 * 1024
MAX_ENVELOPE_DEPTH = 8
LEDGER_TABLE_SQL = {
    "metadata": "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "accounts": "CREATE TABLE accounts (id TEXT PRIMARY KEY, public_key TEXT NOT NULL, "
                "epoch INTEGER NOT NULL, nonce INTEGER NOT NULL, balance INTEGER NOT NULL)",
    "events": "CREATE TABLE events (id TEXT PRIMARY KEY, body TEXT NOT NULL)",
}
LEDGER_SCHEMA = {
    "metadata": [("key", "TEXT", 0, None, 1), ("value", "TEXT", 1, None, 0)],
    "accounts": [("id", "TEXT", 0, None, 1), ("public_key", "TEXT", 1, None, 0),
                 ("epoch", "INTEGER", 1, None, 0), ("nonce", "INTEGER", 1, None, 0),
                 ("balance", "INTEGER", 1, None, 0)],
    "events": [("id", "TEXT", 0, None, 1), ("body", "TEXT", 1, None, 0)],
}


def snapshot_envelope(envelope):
    """Detach bounded plain JSON before authentication or ledger mutation.

    The byte budget counts the complete ASCII JSON representation, including
    keys, escapes and punctuation. Reject large containers/strings before
    copying or serializing them; no caller-owned mutable value is retained.
    """
    remaining = MAX_ENVELOPE_BYTES

    def consume(size):
        nonlocal remaining
        remaining -= size
        if remaining < 0:
            raise ValueError("envelope exceeds size limit")

    def detach(value, depth):
        if depth > MAX_ENVELOPE_DEPTH:
            raise ValueError("envelope exceeds depth limit")
        kind = type(value)
        if kind is dict:
            consume(2 + max(0, len(value) - 1) + len(value))
            result = {}
            for key, child in value.items():
                if type(key) is not str:
                    raise ValueError("envelope keys must be strings")
                result[detach(key, depth + 1)] = detach(child, depth + 1)
            return result
        if kind is list:
            consume(2 + max(0, len(value) - 1))
            return [detach(child, depth + 1) for child in value]
        if kind is str:
            if len(value) > remaining:
                raise ValueError("envelope exceeds size limit")
        elif kind is int:
            if value.bit_length() > 64:
                raise ValueError("envelope integer is out of range")
        elif kind not in (bool, float, type(None)):
            raise ValueError("envelope must contain plain JSON values")
        consume(len(json.dumps(value, ensure_ascii=True, allow_nan=False)))
        return value

    return detach(envelope, 0)


def decode_hex(value, size):
    if not isinstance(value, str) or len(value) != size * 2 or not re.fullmatch(r"[0-9a-f]+", value):
        raise ValueError("noncanonical key/signature encoding")
    return bytes.fromhex(value)


def public_hex(key):
    return key.public_key().public_bytes_raw().hex()


def account_id(key_hex):
    key = decode_hex(key_hex, PUBLIC_KEY_BYTES)
    return "aur3" + hashlib.sha3_256(b"Aurion/v3/account/ML-DSA-65\x00" + key).hexdigest()


def command_bytes(body):
    if not isinstance(body, dict) or set(body) != {"version", "chain", "account", "nonce", "epoch", "action", "payload"}:
        raise ValueError("invalid command fields")
    if type(body["version"]) is not int or body["version"] != 3:
        raise ValueError("unsupported version")
    if not isinstance(body["chain"], str) or not re.fullmatch(r"aurion-upgrade-devnet:[a-z0-9-]{1,48}", body["chain"]):
        raise ValueError("only isolated upgrade devnets are supported")
    if not isinstance(body["account"], str) or not ACCOUNT_RE.fullmatch(body["account"]):
        raise ValueError("invalid account")
    if any(type(body[k]) is not int or not 0 <= body[k] < 2**53 - 1 for k in ("nonce", "epoch")):
        raise ValueError("invalid sequence or epoch")
    p = body["payload"]
    if not isinstance(p, dict):
        raise ValueError("invalid payload")
    if body["action"] == "transfer":
        if set(p) != {"to", "amount"} or not isinstance(p["to"], str) or not ACCOUNT_RE.fullmatch(p["to"]):
            raise ValueError("invalid transfer")
        # Decimal strings prevent JavaScript float rounding and alternate encodings.
        if not isinstance(p["amount"], str) or not re.fullmatch(r"[1-9][0-9]{0,15}", p["amount"]) or int(p["amount"]) > MAX_UNITS:
            raise ValueError("invalid amount")
    elif body["action"] == "rotate":
        if set(p) != {"new_public_key"}:
            raise ValueError("invalid rotation")
        decode_hex(p["new_public_key"], PUBLIC_KEY_BYTES)
    else:
        raise ValueError("unsupported action")
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sign_command(key, body, new_key=None):
    message = command_bytes(body)
    envelope = {"body": json.loads(message), "public_key": public_hex(key),
                "signature": key.sign(message, CONTEXT).hex()}
    if body["action"] == "rotate":
        if new_key is None or public_hex(new_key) != body["payload"]["new_public_key"]:
            raise ValueError("rotation requires possession of the new private key")
        envelope["new_key_signature"] = new_key.sign(message, ROTATION_CONTEXT).hex()
    elif new_key is not None:
        raise ValueError("unexpected new key")
    return envelope


def _verify_snapshot(envelope):
    if not isinstance(envelope, dict) or "body" not in envelope:
        raise ValueError("invalid envelope")
    message = command_bytes(envelope["body"])
    rotating = envelope["body"]["action"] == "rotate"
    fields = {"body", "public_key", "signature"} | ({"new_key_signature"} if rotating else set())
    if set(envelope) != fields:
        raise ValueError("invalid envelope fields")
    key = MLDSA65PublicKey.from_public_bytes(decode_hex(envelope["public_key"], PUBLIC_KEY_BYTES))
    try:
        key.verify(decode_hex(envelope["signature"], SIGNATURE_BYTES), message, CONTEXT)
        if rotating:
            new_key = MLDSA65PublicKey.from_public_bytes(decode_hex(envelope["body"]["payload"]["new_public_key"], PUBLIC_KEY_BYTES))
            new_key.verify(decode_hex(envelope["new_key_signature"], SIGNATURE_BYTES), message, ROTATION_CONTEXT)
    except InvalidSignature as exc:
        raise ValueError("invalid ML-DSA signature") from exc
    return json.loads(message)


def verify_command(envelope):
    return _verify_snapshot(snapshot_envelope(envelope))


class DevLedger:
    """Durable local transaction/rotation harness; no fork choice or consensus.

    BEGIN IMMEDIATE fences concurrent writers, and key/nonce/balance/event writes
    commit together. Stateless signing avoids one-time-key reuse when a signer
    restores an older seed; the ledger still rejects replayed sequence numbers.
    """
    def __init__(self, path, chain="aurion-upgrade-devnet:local"):
        if not re.fullmatch(r"aurion-upgrade-devnet:[a-z0-9-]{1,48}", chain):
            raise ValueError("mainnet is not supported")
        self.chain = chain
        self.db = sqlite3.connect(path, isolation_level=None)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("BEGIN IMMEDIATE")
            existing_objects = self.db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master "
                                               "WHERE name NOT GLOB 'sqlite_*'").fetchall()
            self.db.execute(LEDGER_TABLE_SQL["metadata"].replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
            stored = self.db.execute("SELECT value FROM metadata WHERE key='chain'").fetchone()
            if stored is None and existing_objects:
                raise ValueError("stored chain metadata missing for existing ledger")
            if stored is not None and stored[0] != chain:
                raise ValueError("stored chain mismatch")
            if existing_objects:
                if (len(existing_objects) != len(LEDGER_SCHEMA)
                        or {(row[0], row[1], row[2]) for row in existing_objects}
                        != {("table", name, name) for name in LEDGER_SCHEMA}):
                    raise ValueError("stored ledger schema mismatch; unexpected or missing objects")
                # Whitespace changed between the original and current constructor.
                # Every other DDL token must match: table_info alone omits CHECK,
                # ON CONFLICT, UNIQUE, collations, triggers and table options.
                for _, table, _, sql in existing_objects:
                    if sql is None or " ".join(sql.split()) != LEDGER_TABLE_SQL[table]:
                        raise ValueError("stored ledger schema mismatch; altered table definition")
                autoindexes = self.db.execute("SELECT name,tbl_name,sql FROM sqlite_master "
                                             "WHERE type='index' AND name GLOB 'sqlite_autoindex_*'").fetchall()
                if set(autoindexes) != {("sqlite_autoindex_" + name + "_1", name, None)
                                        for name in LEDGER_SCHEMA}:
                    raise ValueError("stored ledger schema mismatch; unexpected primary-key indexes")
                for table, expected in LEDGER_SCHEMA.items():
                    columns = [(row[1], row[2].upper(), row[3], row[4], row[5])
                               for row in self.db.execute("PRAGMA table_info(" + table + ")")]
                    if columns != expected:
                        raise ValueError("stored ledger schema mismatch; do not repair unknown state")
                    index_name = "sqlite_autoindex_" + table + "_1"
                    indexes = self.db.execute("PRAGMA index_list(" + table + ")").fetchall()
                    index_columns = self.db.execute("PRAGMA index_info(" + index_name + ")").fetchall()
                    if (len(indexes) != 1 or indexes[0][1:] != (index_name, 1, "pk", 0)
                            or index_columns != [(0, 0, expected[0][0])]):
                        raise ValueError("stored ledger schema mismatch; altered primary-key index")
            for table in ("accounts", "events"):
                self.db.execute(LEDGER_TABLE_SQL[table].replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('chain', ?)", (chain,))
            self.db.execute("COMMIT")
        except BaseException:
            try:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
            finally:
                self.close()
            raise

    def close(self):
        self.db.close()

    def register_test_account(self, public_key, balance=0):
        if type(balance) is not int or not 0 <= balance <= MAX_UNITS:
            raise ValueError("invalid test balance")
        address = account_id(public_key)
        self.db.execute("INSERT INTO accounts VALUES (?, ?, 0, 0, ?)", (address, public_key, balance))
        return address

    def account(self, address):
        row = self.db.execute("SELECT public_key,epoch,nonce,balance FROM accounts WHERE id=?", (address,)).fetchone()
        if row is None:
            raise ValueError("unknown account")
        return dict(zip(("public_key", "epoch", "nonce", "balance"), row))

    def apply(self, envelope):
        snapshot = snapshot_envelope(envelope)
        body = _verify_snapshot(snapshot)
        if body["chain"] != self.chain:
            raise ValueError("wrong chain")
        # Content hash is independent of randomized signature bytes.
        ident = hashlib.sha3_256(command_bytes(body)).hexdigest()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            state = self.account(body["account"])
            if (snapshot["public_key"] != state["public_key"] or body["epoch"] != state["epoch"]
                    or body["nonce"] != state["nonce"]):
                raise ValueError("retired key, wrong epoch or replayed sequence")
            if body["action"] == "rotate":
                new = body["payload"]["new_public_key"]
                if new == state["public_key"]:
                    raise ValueError("rotation requires a different key")
                self.db.execute("UPDATE accounts SET public_key=?,epoch=epoch+1,nonce=nonce+1 WHERE id=?", (new, body["account"]))
            else:
                to, amount = body["payload"]["to"], int(body["payload"]["amount"])
                recipient = self.account(to)
                if amount > state["balance"] or (to != body["account"] and recipient["balance"] + amount > MAX_UNITS):
                    raise ValueError("insufficient balance or recipient overflow")
                self.db.execute("UPDATE accounts SET balance=balance-?,nonce=nonce+1 WHERE id=?", (amount, body["account"]))
                self.db.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (amount, to))
            self.db.execute("INSERT INTO events VALUES (?,?)", (ident, json.dumps(snapshot, sort_keys=True, separators=(",", ":"))))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return ident
