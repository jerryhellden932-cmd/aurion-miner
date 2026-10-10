"""Standard-signature candidate tests, separate from legacy consensus tests."""
import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from unittest import mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from upgrade import protocol as pq
except ImportError:
    pq = None


@unittest.skipIf(pq is None, "Install upgrade/requirements.txt for ML-DSA candidate tests")
class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "devnet.db")
        self.key = pq.MLDSA65PrivateKey.generate()
        self.other = pq.MLDSA65PrivateKey.generate()
        self.ledger = pq.DevLedger(self.path)
        self.addCleanup(lambda: self.ledger.close())
        self.address = self.ledger.register_test_account(pq.public_hex(self.key), 100)
        self.to = self.ledger.register_test_account(pq.public_hex(self.other))

    def body(self, **fields):
        return {"version": 3, "chain": self.ledger.chain, "account": self.address,
                "nonce": 0, "epoch": 0, "action": "transfer",
                "payload": {"to": self.to, "amount": "25"}, **fields}

    def test_transfer_restart_and_replay_rejection(self):
        envelope = pq.sign_command(self.key, self.body())
        self.ledger.apply(envelope)
        self.ledger.close()
        self.ledger = pq.DevLedger(self.path)
        self.assertEqual(self.ledger.account(self.address)["balance"], 75)
        self.assertEqual(self.ledger.account(self.to)["balance"], 25)
        with self.assertRaisesRegex(ValueError, "sequence"):
            self.ledger.apply(envelope)

    def test_rotation_requires_both_keys_and_retires_old_key(self):
        new = pq.MLDSA65PrivateKey.generate()
        body = self.body(action="rotate", payload={"new_public_key": pq.public_hex(new)})
        with self.assertRaises(ValueError):
            pq.sign_command(self.key, body)
        rotation = pq.sign_command(self.key, body, new)
        self.ledger.apply(rotation)
        with self.assertRaises(ValueError):
            self.ledger.apply(pq.sign_command(self.key, self.body(nonce=1, epoch=1)))
        self.ledger.apply(pq.sign_command(new, self.body(nonce=1, epoch=1)))
        self.assertEqual(self.ledger.account(self.address)["balance"], 75)

    def test_changed_rotation_proof_and_fields_rejected(self):
        new = pq.MLDSA65PrivateKey.generate()
        env = pq.sign_command(self.key, self.body(action="rotate", payload={"new_public_key": pq.public_hex(new)}), new)
        env["new_key_signature"] = "00" * pq.SIGNATURE_BYTES
        with self.assertRaises(ValueError):
            self.ledger.apply(env)
        self.assertEqual(self.ledger.account(self.address)["epoch"], 0)

    def test_standard_key_sizes_tampering_and_domain_separation(self):
        env = pq.sign_command(self.key, self.body())
        self.assertEqual(len(bytes.fromhex(env["public_key"])), 1952)
        self.assertEqual(len(bytes.fromhex(env["signature"])), 3309)
        for field, value in (("nonce", 1), ("chain", "aurion-upgrade-devnet:other"), ("epoch", 1)):
            changed = copy.deepcopy(env)
            changed["body"][field] = value
            with self.assertRaises(ValueError):
                self.ledger.apply(changed)
        env["signature"] = self.key.sign(pq.command_bytes(env["body"]), b"wrong-domain").hex()
        with self.assertRaises(ValueError):
            self.ledger.apply(env)

    def test_restored_seed_can_sign_new_messages_without_one_time_key_reuse(self):
        restored = pq.MLDSA65PrivateKey.from_seed_bytes(self.key.private_bytes_raw())
        self.ledger.apply(pq.sign_command(self.key, self.body()))
        self.ledger.apply(pq.sign_command(restored, self.body(nonce=1)))
        self.assertEqual(self.ledger.account(self.address)["balance"], 50)

    def test_failed_commit_rolls_back_balances_and_nonce(self):
        self.ledger.db.execute("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'disk failure'); END")
        with self.assertRaises(Exception):
            self.ledger.apply(pq.sign_command(self.key, self.body()))
        self.assertEqual(self.ledger.account(self.address)["balance"], 100)
        self.assertEqual(self.ledger.account(self.address)["nonce"], 0)
        self.assertEqual(self.ledger.account(self.to)["balance"], 0)

    def test_mainnet_and_noncanonical_values_rejected(self):
        with self.assertRaises(ValueError):
            pq.DevLedger(":memory:", "aurion-mainnet")
        for values in ({"nonce": True}, {"epoch": -1}, {"chain": "aurion-mainnet"},
                       {"payload": {"to": self.to, "amount": "025"}},
                       {"payload": {"to": self.to, "amount": 25}}, {"version": 3.0}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                pq.sign_command(self.key, self.body(**values))

    def test_concurrent_ledgers_recheck_current_key_and_nonce(self):
        other = pq.DevLedger(self.path)
        self.addCleanup(other.close)
        envelope = pq.sign_command(self.key, self.body())
        self.ledger.apply(envelope)
        with self.assertRaises(ValueError):
            other.apply(envelope)

    def test_caller_key_mutation_after_verification_cannot_authorize_another_account(self):
        # The attacker really signs a command targeting the victim account.
        envelope = pq.sign_command(self.other, self.body())
        mutated = []

        def mutate_at_begin(sql):
            if sql == "BEGIN IMMEDIATE":
                envelope["public_key"] = pq.public_hex(self.key)
                mutated.append(True)

        self.ledger.db.set_trace_callback(mutate_at_begin)
        with self.assertRaisesRegex(ValueError, "retired key"):
            self.ledger.apply(envelope)
        self.assertEqual(mutated, [True], "the mutation must run after signature verification")
        self.assertEqual(self.ledger.account(self.address)["balance"], 100)
        self.assertEqual(self.ledger.account(self.address)["nonce"], 0)
        self.assertEqual(self.ledger.account(self.to)["balance"], 0)
        self.assertEqual(self.ledger.db.execute("SELECT count(*) FROM events").fetchone()[0], 0)

    def test_persisted_event_keeps_the_exact_verified_snapshot_after_caller_mutation(self):
        envelope = pq.sign_command(self.key, self.body())
        original = copy.deepcopy(envelope)
        mutated = []

        def mutate_at_begin(sql):
            if sql == "BEGIN IMMEDIATE":
                envelope["body"]["payload"]["amount"] = "99"
                envelope["signature"] = "00" * pq.SIGNATURE_BYTES
                mutated.append(True)

        self.ledger.db.set_trace_callback(mutate_at_begin)
        ident = self.ledger.apply(envelope)
        self.assertEqual(mutated, [True])
        stored = json.loads(self.ledger.db.execute("SELECT body FROM events WHERE id=?", (ident,)).fetchone()[0])
        self.assertEqual(stored, original)
        self.assertEqual(pq.verify_command(stored), original["body"])
        self.assertEqual(ident, hashlib.sha3_256(pq.command_bytes(original["body"])).hexdigest())
        self.assertEqual(self.ledger.account(self.address)["balance"], 75)
        self.assertEqual(self.ledger.account(self.to)["balance"], 25)
        self.assertEqual(self.ledger.account(self.address)["nonce"], 1)
        with self.assertRaises(ValueError):
            pq.verify_command(envelope)

    def test_envelope_size_and_depth_bounds_reject_before_starting_a_write(self):
        statements = []
        self.ledger.db.set_trace_callback(statements.append)
        large = pq.sign_command(self.key, self.body())
        large["extra"] = "x" * 32769
        deep = pq.sign_command(self.key, self.body())
        nested = None
        for _ in range(10):
            nested = {"nested": nested}
        deep["extra"] = nested
        for envelope, message in ((large, "size"), (deep, "depth")):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.ledger.apply(envelope)
                with self.assertRaisesRegex(ValueError, message):
                    pq.verify_command(envelope)
        self.assertNotIn("BEGIN IMMEDIATE", statements)
        self.assertEqual(self.ledger.account(self.address)["balance"], 100)

    def test_wrong_stored_chain_does_not_create_or_change_schema(self):
        path = str(Path(self.temp.name) / "other-chain.db")
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO metadata VALUES ('chain', 'aurion-upgrade-devnet:other')")
            before = db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
        with self.assertRaisesRegex(ValueError, "stored chain mismatch"):
            pq.DevLedger(path)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall(), before)
            self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='chain'").fetchone()[0], "aurion-upgrade-devnet:other")

    def test_failed_initialization_rolls_back_schema_and_closes_connection(self):
        path = str(Path(self.temp.name) / "failed-init.db")
        connection = sqlite3.connect(path, isolation_level=None)
        self.addCleanup(connection.close)
        connection.set_authorizer(lambda action, name, *_:
            sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_CREATE_TABLE and name == "accounts" else sqlite3.SQLITE_OK)
        with mock.patch.object(pq.sqlite3, "connect", return_value=connection):
            with self.assertRaises(sqlite3.DatabaseError):
                pq.DevLedger(path)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(), [])
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

    def test_missing_chain_metadata_cannot_relabel_existing_ledger_or_change_state(self):
        for remove_table in (False, True):
            with self.subTest(remove_table=remove_table):
                path = str(Path(self.temp.name) / ("missing-chain-table.db" if remove_table else "missing-chain-row.db"))
                ledger = pq.DevLedger(path, "aurion-upgrade-devnet:original")
                try:
                    ledger.register_test_account(pq.public_hex(self.key), 100)
                    if remove_table:
                        ledger.db.execute("DROP TABLE metadata")
                    else:
                        ledger.db.execute("DELETE FROM metadata WHERE key='chain'")
                    schema = ledger.db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
                    accounts = ledger.db.execute("SELECT * FROM accounts ORDER BY id").fetchall()
                    events = ledger.db.execute("SELECT * FROM events ORDER BY id").fetchall()
                finally:
                    ledger.close()
                with self.assertRaisesRegex(ValueError, "chain metadata missing"):
                    pq.DevLedger(path, "aurion-upgrade-devnet:replacement")
                with sqlite3.connect(path) as db:
                    self.assertEqual(db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall(), schema)
                    self.assertEqual(db.execute("SELECT * FROM accounts ORDER BY id").fetchall(), accounts)
                    self.assertEqual(db.execute("SELECT * FROM events ORDER BY id").fetchall(), events)
                    if not remove_table:
                        self.assertEqual(db.execute("SELECT * FROM metadata").fetchall(), [])

    def test_missing_accounts_or_events_after_signed_transfer_cannot_be_recreated(self):
        for missing in ("accounts", "events"):
            with self.subTest(missing=missing):
                path = str(Path(self.temp.name) / ("missing-" + missing + ".db"))
                ledger = pq.DevLedger(path)
                try:
                    ledger.register_test_account(pq.public_hex(self.key), 100)
                    ledger.register_test_account(pq.public_hex(self.other))
                    ledger.apply(pq.sign_command(self.key, self.body()))
                    self.assertEqual(ledger.account(self.address)["balance"], 75)
                    self.assertEqual(ledger.account(self.to)["balance"], 25)
                    ledger.db.execute("DROP TABLE " + missing)
                    schema = ledger.db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
                    tables = {"metadata", "accounts", "events"} - {missing}
                    rows = {table: ledger.db.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall() for table in tables}
                finally:
                    ledger.close()
                with self.assertRaisesRegex(ValueError, "schema mismatch"):
                    pq.DevLedger(path)
                with sqlite3.connect(path) as db:
                    self.assertEqual(db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall(), schema)
                    for table, expected in rows.items():
                        self.assertEqual(db.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall(), expected)

    def test_changed_columns_after_signed_transfer_are_refused_without_rewriting_state(self):
        self.ledger.apply(pq.sign_command(self.key, self.body()))
        self.ledger.db.execute("ALTER TABLE accounts ADD COLUMN unexpected TEXT")
        schema = self.ledger.db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
        rows = {table: self.ledger.db.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall()
                for table in ("metadata", "accounts", "events")}
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            pq.DevLedger(self.path)
        self.assertEqual(self.ledger.db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall(), schema)
        for table, expected in rows.items():
            self.assertEqual(self.ledger.db.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall(), expected)

    def database_snapshot(self, db):
        return (db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name").fetchall(),
                {table: db.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall()
                 for table in ("metadata", "accounts", "events")})

    def assert_reopen_refused_without_mutation(self, path, expected):
        try:
            reopened = pq.DevLedger(path)
        except ValueError as exc:
            self.assertIn("schema mismatch", str(exc))
        else:
            reopened.close()
            self.fail("an altered candidate schema must not reopen")
        with sqlite3.connect(path) as db:
            self.assertEqual(self.database_snapshot(db), expected)

    def test_unexpected_trigger_view_and_index_preserve_existing_signed_history_on_refusal(self):
        objects = {
            "trigger": "CREATE TRIGGER inflate AFTER UPDATE OF balance ON accounts "
                       "WHEN NEW.balance > OLD.balance BEGIN "
                       "UPDATE accounts SET balance=balance+1 WHERE id=NEW.id; END",
            # LIKE 'sqlite_%' treats the underscore as a wildcard and hides this name.
            "sqliteXevil": "CREATE TRIGGER sqliteXevil AFTER UPDATE OF balance ON accounts "
                           "WHEN NEW.balance > OLD.balance BEGIN "
                           "UPDATE accounts SET balance=balance+1 WHERE id=NEW.id; END",
            "view": "CREATE VIEW unexpected_view AS SELECT * FROM accounts",
            "index": "CREATE INDEX unexpected_index ON accounts(balance)",
        }
        for label, sql in objects.items():
            with self.subTest(object=label):
                path = str(Path(self.temp.name) / ("unexpected-" + label + ".db"))
                ledger = pq.DevLedger(path)
                try:
                    ledger.register_test_account(pq.public_hex(self.key), 100)
                    ledger.register_test_account(pq.public_hex(self.other))
                    ledger.apply(pq.sign_command(self.key, self.body()))
                    self.assertEqual(ledger.account(self.address)["balance"], 75)
                    self.assertEqual(ledger.account(self.to)["balance"], 25)
                    ledger.db.execute(sql)
                    expected = self.database_snapshot(ledger.db)
                finally:
                    ledger.close()
                self.assert_reopen_refused_without_mutation(path, expected)

    def test_altered_constraints_and_options_preserve_existing_signed_history_on_refusal(self):
        columns = "id TEXT PRIMARY KEY, public_key TEXT NOT NULL, epoch INTEGER NOT NULL, " \
                  "nonce INTEGER NOT NULL, balance INTEGER NOT NULL"
        forms = {
            "conflict": "CREATE TABLE accounts (" + columns.replace("PRIMARY KEY", "PRIMARY KEY ON CONFLICT REPLACE") + ")",
            "unique": "CREATE TABLE accounts (" + columns + ", UNIQUE(public_key))",
            "check": "CREATE TABLE accounts (" + columns + ", CHECK(balance>=0))",
            "without-rowid": "CREATE TABLE accounts (" + columns + ") WITHOUT ROWID",
            "strict": "CREATE TABLE accounts (" + columns + ") STRICT",
        }
        for label, sql in forms.items():
            with self.subTest(form=label):
                path = str(Path(self.temp.name) / ("altered-" + label + ".db"))
                ledger = pq.DevLedger(path)
                try:
                    ledger.register_test_account(pq.public_hex(self.key), 100)
                    ledger.register_test_account(pq.public_hex(self.other))
                    ledger.apply(pq.sign_command(self.key, self.body()))
                    ledger.db.execute("ALTER TABLE accounts RENAME TO previous_accounts")
                    ledger.db.execute(sql)
                    ledger.db.execute("INSERT INTO accounts SELECT * FROM previous_accounts")
                    ledger.db.execute("DROP TABLE previous_accounts")
                    if label == "unique":
                        self.assertIsNotNone(ledger.db.execute("SELECT name FROM sqlite_master "
                                                              "WHERE name='sqlite_autoindex_accounts_2'").fetchone())
                    expected = self.database_snapshot(ledger.db)
                finally:
                    ledger.close()
                self.assert_reopen_refused_without_mutation(path, expected)

    def test_original_multiline_constructor_schema_reopens_without_changing_history(self):
        path = str(Path(self.temp.name) / "original-schema.db")
        with sqlite3.connect(path) as db:
            # The initial candidate constructor emitted this multiline DDL.
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, public_key TEXT NOT NULL,
                  epoch INTEGER NOT NULL, nonce INTEGER NOT NULL, balance INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, body TEXT NOT NULL);
            """)
            db.execute("INSERT INTO metadata VALUES ('chain', ?)", (self.ledger.chain,))
        ledger = pq.DevLedger(path)
        try:
            ledger.register_test_account(pq.public_hex(self.key), 100)
            ledger.register_test_account(pq.public_hex(self.other))
            ident = ledger.apply(pq.sign_command(self.key, self.body()))
            expected = self.database_snapshot(ledger.db)
        finally:
            ledger.close()
        reopened = pq.DevLedger(path)
        try:
            self.assertEqual(self.database_snapshot(reopened.db), expected)
            self.assertEqual(reopened.account(self.address)["balance"], 75)
            self.assertEqual(reopened.account(self.to)["balance"], 25)
            self.assertEqual(reopened.account(self.address)["nonce"], 1)
            event = json.loads(reopened.db.execute("SELECT body FROM events WHERE id=?", (ident,)).fetchone()[0])
            self.assertEqual(pq.verify_command(event), self.body())
        finally:
            reopened.close()


if __name__ == "__main__":
    unittest.main()
