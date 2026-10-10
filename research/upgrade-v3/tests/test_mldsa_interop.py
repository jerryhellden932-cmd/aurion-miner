"""Python and Node native ML-DSA APIs, using separate OpenSSL runtime versions.

This is interoperability evidence, not an independent algorithm implementation,
audit, mainnet activation or browser/Workers qualification. All keys are generated
ephemerally. Public keys use standard SPKI DER serialization, never DER slicing;
contexts must work as specified and are never stripped as a fallback.
"""
import copy
import json
import queue
import shutil
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    from upgrade import protocol as pq
except ImportError:
    pq = None

FIXTURE = Path(__file__).with_name("fixtures") / "mldsa-interop.mjs"
MAX_INPUT = 128 * 1024
MAX_OUTPUT = 64 * 1024


class NodeSession:
    """Two public JSON messages, with bounded pipes and one total deadline."""
    def __init__(self, executable):
        self.deadline = time.monotonic() + 15
        self.lines = queue.Queue()
        self.stderr = bytearray()
        self.writer = None
        self.process = subprocess.Popen([executable, str(FIXTURE)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.readers = [threading.Thread(target=self._stdout, daemon=True),
                        threading.Thread(target=self._stderr, daemon=True)]
        for thread in self.readers:
            thread.start()

    def _stdout(self):
        total = 0
        try:
            while True:
                line = self.process.stdout.readline(MAX_OUTPUT + 1)
                total += len(line)
                if total > MAX_OUTPUT:
                    self.process.kill()
                    self.lines.put(RuntimeError("Node fixture exceeded its output limit"))
                    return
                if not line:
                    self.lines.put(RuntimeError("Node fixture ended without the expected message"))
                    return
                self.lines.put(line)
        except Exception as error:
            self.lines.put(error)

    def _stderr(self):
        while True:
            chunk = self.process.stderr.read1(4096)
            if not chunk:
                return
            if len(self.stderr) + len(chunk) > 8192:
                self.process.kill()
                self.lines.put(RuntimeError("Node fixture exceeded its diagnostic limit"))
                return
            self.stderr.extend(chunk)

    def receive(self):
        try:
            line = self.lines.get(timeout=max(0.001, self.deadline - time.monotonic()))
        except queue.Empty as error:
            raise RuntimeError("Node ML-DSA fixture timed out") from error
        if isinstance(line, Exception):
            raise line
        return json.loads(line)

    def call(self, request):
        encoded = json.dumps(request, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > MAX_INPUT:
            raise ValueError("Node fixture request exceeds size limit")
        written = queue.Queue()

        def write():
            try:
                self.process.stdin.write(encoded)
                self.process.stdin.close()
                written.put(None)
            except Exception as error:
                written.put(error)

        self.writer = threading.Thread(target=write, daemon=True)
        self.writer.start()
        try:
            error = written.get(timeout=max(0.001, self.deadline - time.monotonic()))
        except queue.Empty as error:
            raise RuntimeError("Node ML-DSA fixture input timed out") from error
        if error is not None:
            raise error
        result = self.receive()
        self.process.wait(timeout=max(0.001, self.deadline - time.monotonic()))
        for reader in self.readers:
            reader.join(timeout=1)
        if self.process.returncode:
            raise RuntimeError("Node ML-DSA fixture failed: " + self.stderr.decode("utf-8", "replace"))
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=2)
        if self.writer is not None:
            self.writer.join(timeout=1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
        for reader in self.readers:
            reader.join(timeout=1)


@unittest.skipIf(pq is None, "Python native ML-DSA unavailable; install upgrade/requirements.txt")
class MLDSAInteropTests(unittest.TestCase):
    def setUp(self):
        executable = shutil.which("node")
        if executable is None:
            self.skipTest("Node native runtime is not installed")
        self.session = NodeSession(executable)
        self.addCleanup(self.session.close)
        ready = self.session.receive()
        if not ready.get("supported"):
            self.skipTest("Node native ML-DSA/context unsupported: " + ready.get("reason", "unknown reason"))
        self.runtime = ready["runtime"]
        try:
            self.node_current = serialization.load_der_public_key(bytes.fromhex(ready["current_spki"]))
            self.node_replacement = serialization.load_der_public_key(bytes.fromhex(ready["replacement_spki"]))
            self.python_key = pq.MLDSA65PrivateKey.generate()
        except UnsupportedAlgorithm as error:
            self.skipTest("Python native ML-DSA backend unsupported: " + str(error))
        self.assertIsInstance(self.node_current, pq.MLDSA65PublicKey)
        self.assertIsInstance(self.node_replacement, pq.MLDSA65PublicKey)
        self.recipient = pq.account_id(pq.public_hex(self.python_key))

    def body(self, public_key=None, action="transfer", payload=None):
        public_key = public_key or self.python_key.public_key()
        return {"version": 3, "chain": "aurion-upgrade-devnet:interop",
                "account": pq.account_id(public_key.public_bytes_raw().hex()), "nonce": 0,
                "epoch": 0, "action": action, "payload": payload or {"to": self.recipient, "amount": "25"}}

    def record(self, body, context, **extra):
        changed = copy.deepcopy(body)
        changed["nonce"] = 1
        other = pq.ROTATION_CONTEXT if context == pq.CONTEXT else pq.CONTEXT
        return {"message": pq.command_bytes(body).hex(), "changed_message": pq.command_bytes(changed).hex(),
                "context": context.hex(), "other_context": other.hex(), **extra}

    def public_record(self, body, key, signature, context):
        spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return self.record(body, context, public_spki=spki.hex(), signature=signature)

    def assert_native_checks(self, result):
        self.assertEqual(result, {"valid": True, "changed_body": False, "wrong_context": False,
                                  "omitted_context": False, "corrupted_signature": False})

    def test_python_transfer_verifies_in_node_and_rejects_changed_body_or_context(self):
        envelope = pq.sign_command(self.python_key, self.body())
        request = self.public_record(envelope["body"], self.python_key.public_key(), envelope["signature"], pq.CONTEXT)
        result = self.session.call({"verify": [request], "sign": []})
        self.assertEqual(result["signed"], [])
        self.assertEqual(len(result["verified"]), 1)
        self.assert_native_checks(result["verified"][0])

    def test_node_transfer_verifies_in_python_and_rejects_changed_body_or_context(self):
        body = self.body(self.node_current)
        result = self.session.call({"verify": [], "sign": [self.record(body, pq.CONTEXT, key="current")]})
        self.assertEqual(result["verified"], [])
        self.assertEqual(len(result["signed"]), 1)
        signed = result["signed"][0]
        self.assert_native_checks(signed["checks"])
        signature = bytes.fromhex(signed["signature"])
        self.assertEqual(len(signature), pq.SIGNATURE_BYTES)
        self.node_current.verify(signature, pq.command_bytes(body), pq.CONTEXT)
        envelope = {"body": body, "public_key": self.node_current.public_bytes_raw().hex(), "signature": signed["signature"]}
        self.assertEqual(pq.verify_command(envelope), body)
        changed = copy.deepcopy(envelope); changed["body"]["nonce"] = 1
        with self.assertRaises(ValueError):
            pq.verify_command(changed)
        for context in (pq.ROTATION_CONTEXT, b""):
            with self.subTest(context=context), self.assertRaises(InvalidSignature):
                self.node_current.verify(signature, pq.command_bytes(body), context)

    def test_python_rotation_proofs_verify_in_node_with_separate_contexts(self):
        replacement = pq.MLDSA65PrivateKey.generate()
        body = self.body(action="rotate", payload={"new_public_key": pq.public_hex(replacement)})
        envelope = pq.sign_command(self.python_key, body, replacement)
        records = [self.public_record(body, self.python_key.public_key(), envelope["signature"], pq.CONTEXT),
                   self.public_record(body, replacement.public_key(), envelope["new_key_signature"], pq.ROTATION_CONTEXT)]
        result = self.session.call({"verify": records, "sign": []})
        self.assertEqual(len(result["verified"]), 2)
        for verified in result["verified"]:
            self.assert_native_checks(verified)

    def test_node_rotation_proofs_verify_in_python_and_reject_context_swap(self):
        body = self.body(self.node_current, action="rotate", payload={"new_public_key": self.node_replacement.public_bytes_raw().hex()})
        records = [self.record(body, pq.CONTEXT, key="current"),
                   self.record(body, pq.ROTATION_CONTEXT, key="replacement")]
        result = self.session.call({"verify": [], "sign": records})
        self.assertEqual(len(result["signed"]), 2)
        for signed in result["signed"]:
            self.assert_native_checks(signed["checks"])
        envelope = {"body": body, "public_key": self.node_current.public_bytes_raw().hex(),
                    "signature": result["signed"][0]["signature"], "new_key_signature": result["signed"][1]["signature"]}
        self.assertEqual(pq.verify_command(envelope), body)
        changed = copy.deepcopy(envelope); changed["body"]["nonce"] = 1
        with self.assertRaises(ValueError):
            pq.verify_command(changed)
        for key, signed, context in ((self.node_current, envelope["signature"], pq.ROTATION_CONTEXT),
                                     (self.node_replacement, envelope["new_key_signature"], pq.CONTEXT)):
            with self.subTest(context=context), self.assertRaises(InvalidSignature):
                key.verify(bytes.fromhex(signed), pq.command_bytes(body), context)


if __name__ == "__main__":
    unittest.main()
