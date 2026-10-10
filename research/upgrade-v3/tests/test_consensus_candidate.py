"""Offline candidate tests; synthetic DAG models are NOT native mining evidence."""
import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import random
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
try:
    from upgrade import consensus as candidate
except ImportError:
    candidate = None

MODEL_EVIDENCE = {"kind": "synthetic-signature-and-DAG-model-only", "proof_of_space_verified": False,
                  "independent_network_verified": False, "real_funds_ready": False}


def keys():
    return (candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(bytes(range(32))),
            candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(bytes(range(32, 64))))


def registration(lab, owner, nonce=b"n" * 32, k=18):
    public = candidate.protocol.public_hex(owner)
    body = {"version": 3, "chain": lab._configuration["chain"], "genesis": lab.genesis,
            "owner": public, "nonce": nonce.hex(), "k": k,
            "plot_id": candidate.storage.plot_identity(lab._configuration["chain"], bytes.fromhex(public), nonce, k).hex()}
    return candidate.sign(owner, body, "registration")


def beacon(lab, key, round_number):
    return candidate.sign(key, {"version": 3, "chain": lab._configuration["chain"], "genesis": lab.genesis,
        "round": round_number, "challenge": lab._rounds[round_number]}, "beacon")


@unittest.skipIf(candidate is None, "ML-DSA candidate dependency unavailable")
class SyntheticDAGModelTests(unittest.TestCase):
    """Only signatures, detachment and graph rules; ALL space proofs are mocked."""
    def setUp(self):
        self.owner, self.beacon_key = keys()
        self.chain = "aurion-upgrade-devnet:synthetic-dag-model"
        self.rounds = {i: hashlib.sha256(b"predictable-lab-round" + i.to_bytes(4, "big")).hexdigest() for i in range(1, 129)}
        self.native = mock.patch.object(candidate, "require_native", return_value=None)
        self.quality = mock.patch.object(candidate.storage, "verify_space", side_effect=lambda pid, k, challenge, proof: bytes([proof[0]]) + b"\x00" * 31)
        self.native.start()
        self.quality.start()
        self.addCleanup(self.native.stop)
        self.addCleanup(self.quality.stop)

    def lab(self, **caps):
        return candidate.Rehearsal(self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds, **caps)

    def prepare(self, lab, rounds=(1, 2, 3)):
        signed = registration(lab, self.owner)
        plot_id = lab.register_plot(signed)
        for round_number in rounds:
            lab.accept_beacon(beacon(lab, self.beacon_key, round_number))
        return plot_id

    def checkpoint(self, lab, plot_id, parent=None, first_quality_byte=255):
        parent = parent or lab.genesis
        state = lab._headers[parent]
        public = candidate.protocol.public_hex(self.owner)
        return candidate.sign(self.owner, {"version": 3, "chain": self.chain, "genesis": lab.genesis,
            "parent": parent, "height": state.height + 1, "round": state.height + 1, "owner": public,
            "sequence": state.sequences.get(public, 0), "plot_id": plot_id,
            "proof": (bytes([first_quality_byte]) * (8 * 18)).hex()}, "checkpoint")

    def test_model_evidence_never_claims_native_or_production_verification(self):
        lab = self.lab()
        pid = self.prepare(lab)
        lab.add_checkpoint(self.checkpoint(lab, pid))
        self.assertFalse(MODEL_EVIDENCE["proof_of_space_verified"])
        self.assertFalse(lab.export()["proof_of_space_verified"])
        for name in ("proof_of_space_verified", "unbiased_randomness_verified", "independent_network_verified",
                     "real_funds_ready", "security_certification", "activation_authorized"):
            self.assertIs(lab.info()[name], False)
        self.assertIn("predictable", lab.info()["notice"])
        self.assertIn("non-economic", lab.info()["notice"])

    def test_production_domains_and_verifier_injection_are_unavailable(self):
        for chain in ("aurion-mainnet", "aurion-testnet", "other", "aurion-upgrade-devnet:"):
            with self.subTest(chain=chain), mock.patch.object(candidate, "require_native", side_effect=AssertionError("must reject domain first")):
                with self.assertRaisesRegex(ValueError, "production"):
                    candidate.Rehearsal(chain, candidate.protocol.public_hex(self.beacon_key), self.rounds)
        for override in ({"verifier": lambda *_: b"x" * 32}, {"production_randomness": True}, {"independent_operators": True}):
            with self.assertRaises(TypeError):
                self.lab(**override)

    def test_genesis_binds_key_schedule_caps_and_detaches_mapping(self):
        schedule = self.rounds.copy()
        lab = candidate.Rehearsal(self.chain, candidate.protocol.public_hex(self.beacon_key), schedule)
        initial = lab.genesis
        schedule[1] = "f" * 64
        self.assertEqual(lab._rounds[1], self.rounds[1])
        changed = self.rounds.copy()
        changed[1] = "f" * 64
        self.assertNotEqual(initial, candidate.Rehearsal(self.chain, candidate.protocol.public_hex(self.beacon_key), changed).genesis)
        self.assertNotEqual(initial, self.lab(max_checkpoints=256).genesis)
        self.assertNotEqual(initial, candidate.Rehearsal(self.chain, candidate.protocol.public_hex(self.owner), self.rounds).genesis)
        for invalid in ({}, {0: "a" * 64}, {1: "a" * 64, 3: "b" * 64}, {1: "a" * 64, 2: "a" * 64}, {"1": "a" * 64}):
            with self.assertRaises(ValueError):
                candidate.Rehearsal(self.chain, candidate.protocol.public_hex(self.beacon_key), invalid)

    def test_registration_binding_and_legacy_claims_rejected(self):
        lab = self.lab()
        signed = registration(lab, self.owner)
        for field, value in (("chain", "aurion-upgrade-devnet:other"), ("genesis", "0" * 64),
                             ("nonce", "a" * 64), ("k", 19), ("plot_id", "b" * 64), ("owner", candidate.protocol.public_hex(self.beacon_key))):
            changed = copy.deepcopy(signed)
            changed["body"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                lab.register_plot(changed)
        for field in ("leaf", "n", "declared_size", "production", "independent_operators"):
            changed = copy.deepcopy(signed)
            changed["body"][field] = 4294967295
            with self.assertRaises(ValueError):
                lab.register_plot(changed)
        self.assertEqual(lab.export()["registrations"], [])

    def test_beacon_authentication_equivocation_unknown_round_and_domain(self):
        lab = self.lab()
        original = beacon(lab, self.beacon_key, 1)
        for field, value in (("round", 129), ("challenge", "0" * 64), ("genesis", "0" * 64), ("round", True)):
            changed = copy.deepcopy(original)
            changed["body"][field] = value
            with self.assertRaises(ValueError):
                lab.accept_beacon(changed)
        wrong_key = candidate.sign(self.owner, original["body"], "beacon")
        with self.assertRaisesRegex(ValueError, "signature"):
            lab.accept_beacon(wrong_key)
        wrong_domain = copy.deepcopy(original)
        wrong_domain["signature"] = self.beacon_key.sign(candidate.encoded(original["body"]), candidate.DOMAINS["checkpoint"]).hex()
        with self.assertRaisesRegex(ValueError, "signature"):
            lab.accept_beacon(wrong_domain)
        with self.assertRaisesRegex(ValueError, "unauthenticated"):
            lab.challenge(1)
        lab.accept_beacon(original)
        self.assertEqual(lab.challenge(1).hex(), self.rounds[1])

    def test_parent_bound_sequences_and_duplicate_signature_identity(self):
        lab = self.lab()
        pid = self.prepare(lab)
        first = self.checkpoint(lab, pid)
        first_id = lab.add_checkpoint(first)
        signature_variant = candidate.sign(self.owner, first["body"], "checkpoint")
        self.assertEqual(lab.add_checkpoint(signature_variant), first_id)
        self.assertEqual(lab.info()["retained_checkpoints"], 1)
        # Equal branch-local sequences on sibling forks are intentional; they
        # are equivocation, not a reuse of a one-time signing key.
        sibling = self.checkpoint(lab, pid, first_quality_byte=254)
        lab.add_checkpoint(sibling)
        child = self.checkpoint(lab, pid, first_id)
        self.assertEqual(child["body"]["sequence"], 1)
        for sequence in (0, 2, True, -1):
            bad = copy.deepcopy(child)
            bad["body"]["sequence"] = sequence
            with self.assertRaises(ValueError):
                lab.add_checkpoint(bad)
        transplant = copy.deepcopy(child)
        transplant["body"]["parent"] = candidate.identifier(sibling["body"])
        with self.assertRaisesRegex(ValueError, "signature"):
            lab.add_checkpoint(transplant)
        lab.add_checkpoint(child)

    def test_challenge_is_fixed_for_round_excludes_producer_header_choices(self):
        lab = self.lab()
        pid = self.prepare(lab)
        lab.add_checkpoint(self.checkpoint(lab, pid, first_quality_byte=255))
        lab.add_checkpoint(self.checkpoint(lab, pid, first_quality_byte=0))
        self.assertEqual(lab.challenge(2).hex(), self.rounds[2])
        for field in ("challenge", "claimed_weight", "leaf", "n", "unbiased_randomness"):
            bad = self.checkpoint(lab, pid)
            bad["body"][field] = "0" * 64
            with self.assertRaises(ValueError):
                lab.add_checkpoint(bad)

    def test_unknown_dependencies_invalid_quality_and_bounds_do_not_enter_dag(self):
        lab = self.lab()
        pid = self.prepare(lab)
        original = self.checkpoint(lab, pid)
        for field, value in (("parent", "0" * 64), ("plot_id", "0" * 64), ("height", 2), ("round", 2), ("proof", "0" * 10000)):
            bad = copy.deepcopy(original)
            bad["body"][field] = value
            with self.assertRaises(ValueError):
                lab.add_checkpoint(bad)
            self.assertEqual(lab.info()["retained_checkpoints"], 0)
        for quality in (b"", b"x" * 31, "0" * 64):
            with mock.patch.object(candidate.storage, "verify_space", return_value=quality), self.assertRaisesRegex(ValueError, "quality"):
                lab.add_checkpoint(original)
        self.assertEqual(lab.info()["retained_checkpoints"], 0)

    def test_signed_inputs_are_detached_before_authentication_and_storage(self):
        lab = self.lab()
        original = registration(lab, self.owner)
        checked = copy.deepcopy(original)
        authenticate = candidate.authenticate
        def mutate_registration(envelope, key, purpose):
            original["body"]["owner"] = "malformed caller mutation"
            original["signature"] = "00"
            return authenticate(envelope, key, purpose)
        with mock.patch.object(candidate, "authenticate", side_effect=mutate_registration):
            pid = lab.register_plot(original)
        self.assertEqual(lab.export()["registrations"], [checked])
        original_beacon = beacon(lab, self.beacon_key, 1)
        def mutate_beacon(envelope, key, purpose):
            original_beacon["body"]["challenge"] = "0" * 64
            return authenticate(envelope, key, purpose)
        with mock.patch.object(candidate, "authenticate", side_effect=mutate_beacon):
            lab.accept_beacon(original_beacon)
        self.assertEqual(lab.challenge(1).hex(), self.rounds[1])
        original_header = self.checkpoint(lab, pid)
        checked_header = copy.deepcopy(original_header)
        def mutate_header(*args):
            original_header["body"]["sequence"] = 999
            original_header["body"]["proof"] = "00"
            return b"\xff" + b"\x00" * 31
        with mock.patch.object(candidate.storage, "verify_space", side_effect=mutate_header):
            lab.add_checkpoint(original_header)
        self.assertEqual(lab.export()["checkpoints"], [checked_header])
        exported = lab.export()
        exported["checkpoints"][0]["body"]["proof"] = "00"
        self.assertEqual(lab.export()["checkpoints"], [checked_header])

    def test_complete_bounded_long_branch_and_heavier_branch_converge_in_permutations(self):
        builder = self.lab()
        pid = self.prepare(builder, range(1, 102))
        long_branch, parent = [], builder.genesis
        for _ in range(101):
            header = self.checkpoint(builder, pid, parent)
            parent = builder.add_checkpoint(header)
            long_branch.append(header)
        heavier = self.checkpoint(builder, pid, first_quality_byte=0)
        heavy_id = builder.add_checkpoint(heavier)
        fixture = builder.export()
        complete = long_branch + [heavier]
        shuffled = complete.copy()
        random.Random(20261010).shuffle(shuffled)
        for delivery in (complete, [heavier] + long_branch, shuffled):
            lab = self.lab()
            for signed in fixture["registrations"]:
                lab.register_plot(signed)
            for signed in fixture["beacons"]:
                lab.accept_beacon(signed)
            pending = delivery.copy()
            # Explicit bounded dependency resubmission, NOT public peer testing.
            for _ in range(len(delivery) + 1):
                unresolved = []
                for signed in pending:
                    try:
                        lab.add_checkpoint(signed)
                    except candidate.MissingParent:
                        unresolved.append(signed)
                if not unresolved:
                    break
                self.assertLess(len(unresolved), len(pending))
                pending = unresolved
            self.assertFalse(unresolved)
            self.assertEqual(lab.best, heavy_id)
            self.assertEqual(lab.info()["laboratory_weight"], 256)
            self.assertEqual(lab.info()["height"], 1)
            self.assertEqual(lab.info()["retained_checkpoints"], 102)
            self.assertEqual(lab.export(), fixture)
        self.assertFalse(MODEL_EVIDENCE["proof_of_space_verified"])

    def test_lab_equal_weight_tie_break_is_height_then_header_hash(self):
        lab = self.lab()
        pid = self.prepare(lab)
        first = lab.add_checkpoint(self.checkpoint(lab, pid))
        child = lab.add_checkpoint(self.checkpoint(lab, pid, first))
        # Height-2 total2 beats a height-1 sibling with total2.
        lab.add_checkpoint(self.checkpoint(lab, pid, first_quality_byte=254))
        self.assertEqual(lab.best, child)
        another = self.checkpoint(lab, pid, first, first_quality_byte=255)
        # Vary the mocked proof after its first byte, keeping the laboratory score.
        another["body"]["proof"] = "ff" + "01" * (8 * 18 - 1)
        another = candidate.sign(self.owner, another["body"], "checkpoint")
        sibling_id = lab.add_checkpoint(another)
        self.assertEqual(lab.best, max(child, sibling_id))

    def test_capacity_overflow_withholds_tip_and_never_prunes_history(self):
        lab = self.lab(max_checkpoints=1)
        pid = self.prepare(lab)
        lab.add_checkpoint(self.checkpoint(lab, pid))
        original = lab.export()["checkpoints"]
        with self.assertRaises(candidate.IncompleteEvaluation):
            lab.add_checkpoint(self.checkpoint(lab, pid, first_quality_byte=0))
        self.assertEqual(lab.export()["checkpoints"], original)
        self.assertFalse(lab.info()["evaluation_complete"])
        self.assertIsNone(lab.info()["best"])
        with self.assertRaises(candidate.IncompleteEvaluation):
            _ = lab.best
        with self.assertRaises(ValueError):
            candidate.Rehearsal.from_export(lab.export(), self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                           expected_packet_sha256=candidate.packet_sha256(lab.export()), max_checkpoints=1)
        lab = self.lab(max_plots=1)
        self.prepare(lab)
        with self.assertRaises(candidate.IncompleteEvaluation):
            lab.register_plot(registration(lab, self.owner, b"m" * 32))
        self.assertFalse(lab.info()["evaluation_complete"])

    def test_replay_requires_external_pins_and_reauthenticates_detached_records(self):
        lab = self.lab()
        pid = self.prepare(lab)
        first = lab.add_checkpoint(self.checkpoint(lab, pid))
        lab.add_checkpoint(self.checkpoint(lab, pid, first))
        packet = lab.export()
        restored = candidate.Rehearsal.from_export(packet, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                                  expected_packet_sha256=candidate.packet_sha256(packet))
        self.assertEqual(restored.export(), packet)
        for field, value in (("genesis", "0" * 64), ("evaluation_complete", False),
                             ("notice", "production ready"), ("proof_of_space_verified", True)):
            bad = copy.deepcopy(packet)
            bad[field] = value
            with self.assertRaises(ValueError):
                candidate.Rehearsal.from_export(bad, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                               expected_packet_sha256=candidate.packet_sha256(bad))
        changed = copy.deepcopy(packet)
        changed["checkpoints"][0]["signature"] = "00" * candidate.protocol.SIGNATURE_BYTES
        with self.assertRaises(ValueError):
            candidate.Rehearsal.from_export(changed, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                           expected_packet_sha256=candidate.packet_sha256(changed))
        authenticate = candidate.authenticate
        def mutate_packet(envelope, public, kind):
            packet["checkpoints"][0]["body"]["height"] = 999
            return authenticate(envelope, public, kind)
        with mock.patch.object(candidate, "authenticate", side_effect=mutate_packet):
            restored = candidate.Rehearsal.from_export(packet, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                                      expected_packet_sha256=candidate.packet_sha256(packet))
        self.assertEqual(restored.info()["height"], 2)

    def test_replay_omissions_and_bool_integer_configuration_aliases_fail_closed(self):
        lab = self.lab(max_checkpoints=1)
        pid = self.prepare(lab)
        lab.add_checkpoint(self.checkpoint(lab, pid))
        packet = lab.export()
        pinned = candidate.packet_sha256(packet)
        omitted = copy.deepcopy(packet)
        omitted["checkpoints"] = []
        with self.assertRaisesRegex(ValueError, "digest"):
            candidate.Rehearsal.from_export(omitted, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                           expected_packet_sha256=pinned, max_checkpoints=1)
        for name in ("rounds", "max_checkpoints"):
            aliased = copy.deepcopy(packet)
            if name == "rounds":
                aliased["configuration"][name][0][0] = True
            else:
                aliased["configuration"][name] = True
            with self.assertRaisesRegex(ValueError, "genesis"):
                candidate.Rehearsal.from_export(aliased, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                               expected_packet_sha256=candidate.packet_sha256(aliased), max_checkpoints=1)
        with self.assertRaises(TypeError):
            candidate.Rehearsal.from_export(packet, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds)

    def test_oversized_and_deep_replay_inputs_are_rejected_before_native_setup(self):
        lab = self.lab()
        packet = lab.export()
        packet["checkpoints"] = [{}] * 2049
        with mock.patch.object(candidate, "require_native", side_effect=AssertionError("must bound before setup")):
            with self.assertRaisesRegex(ValueError, "bounds"):
                candidate.Rehearsal.from_export(packet, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                               expected_packet_sha256="0" * 64)
        packet["checkpoints"] = [[[[[[{}]]]]]]
        with self.assertRaisesRegex(ValueError, "bounded"):
            candidate.Rehearsal.from_export(packet, self.chain, candidate.protocol.public_hex(self.beacon_key), self.rounds,
                                           expected_packet_sha256="0" * 64)


@unittest.skipIf(candidate is None, "ML-DSA candidate dependency unavailable")
class NativeDependencyAndIntegrationTests(unittest.TestCase):
    def bound_fixture(self):
        try:
            candidate.require_native()
        except candidate.MissingDependency as exc:
            self.skipTest(str(exc))
        path = ROOT / "tests/fixtures/space-proof-bound.json"
        if not path.is_file():
            self.skipTest("Owner-bound native fixture absent; no end-to-end mining verification claimed")
        return json.loads(path.read_text())

    def test_missing_and_wrong_native_dependency_fail_closed(self):
        owner, beacon_key = keys()
        config = ("aurion-upgrade-devnet:native", candidate.protocol.public_hex(beacon_key), {1: "a" * 64})
        with mock.patch.object(candidate.importlib.metadata, "version", side_effect=importlib.metadata.PackageNotFoundError("chiapos")):
            with self.assertRaises(candidate.MissingDependency):
                candidate.Rehearsal(*config)
        with mock.patch.object(candidate.importlib.metadata, "version", return_value="0.0.0"):
            with self.assertRaises(candidate.MissingDependency):
                candidate.Rehearsal(*config)

    def test_real_legacy_fixture_verifies_only_standalone_not_owner_registration(self):
        try:
            candidate.require_native()
        except candidate.MissingDependency as exc:
            self.skipTest(str(exc))
        fixture = json.loads((ROOT / "tests/fixtures/space-proof.json").read_text())
        self.assertEqual(candidate.storage.verify_space(bytes.fromhex(fixture["plot_id"]), fixture["k"],
            bytes.fromhex(fixture["challenge"]), bytes.fromhex(fixture["proof"])).hex(), fixture["quality"])
        owner, beacon_key = keys()
        lab = candidate.Rehearsal("aurion-upgrade-devnet:legacy-fixture", candidate.protocol.public_hex(beacon_key), {1: fixture["challenge"]})
        signed = registration(lab, owner)
        signed["body"]["plot_id"] = fixture["plot_id"]
        signed = candidate.sign(owner, signed["body"], "registration")
        with self.assertRaisesRegex(ValueError, "identity"):
            lab.register_plot(signed)

    def test_genuine_owner_bound_native_registration_beacon_and_checkpoint(self):
        fixture = self.bound_fixture()
        owner = candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(fixture["owner_seed"]))
        beacon_key = candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(fixture["beacon_seed"]))
        self.assertEqual(candidate.protocol.public_hex(owner), fixture["owner_public_key"])
        self.assertEqual(candidate.protocol.public_hex(beacon_key), fixture["beacon_public_key"])
        lab = candidate.Rehearsal(fixture["chain"], fixture["beacon_public_key"], {1: fixture["challenge"]})
        signed = registration(lab, owner, bytes.fromhex(fixture["nonce"]), fixture["k"])
        self.assertEqual(lab.register_plot(signed), fixture["plot_id"])
        lab.accept_beacon(beacon(lab, beacon_key, 1))
        body = {"version": 3, "chain": fixture["chain"], "genesis": lab.genesis,
                "parent": lab.genesis, "height": 1, "round": 1, "owner": fixture["owner_public_key"],
                "sequence": 0, "plot_id": fixture["plot_id"], "proof": fixture["proof"]}
        lab.add_checkpoint(candidate.sign(owner, body, "checkpoint"))
        self.assertEqual(lab.info()["retained_checkpoints"], 1)
        self.assertEqual(lab.info()["laboratory_weight"], 256 - bytes.fromhex(fixture["quality"])[0])
        changed = body.copy()
        changed["proof"] = "00" * (fixture["k"] * 8)
        with self.assertRaises(ValueError):
            lab.add_checkpoint(candidate.sign(owner, changed, "checkpoint"))
        self.assertEqual(lab.info()["retained_checkpoints"], 1)
        restored = candidate.Rehearsal.from_export(lab.export(), fixture["chain"], fixture["beacon_public_key"], {1: fixture["challenge"]},
                                                  expected_packet_sha256=candidate.packet_sha256(lab.export()))
        self.assertEqual(restored.export(), lab.export())
        self.assertFalse(lab.info()["real_funds_ready"])

    def test_genuine_native_proof_rejects_changed_plot_challenge_size_and_bytes(self):
        fixture = self.bound_fixture()
        pid, challenge, proof = [bytes.fromhex(fixture[name]) for name in ("plot_id", "challenge", "proof")]
        self.assertEqual(candidate.storage.verify_space(pid, fixture["k"], challenge, proof).hex(), fixture["quality"])
        for args in ((b"\x00" * 32, fixture["k"], challenge, proof),
                     (pid, fixture["k"], b"\x00" * 32, proof),
                     (pid, fixture["k"], challenge, b"\x00" * len(proof)),
                     (pid, fixture["k"] + 1, challenge, proof),
                     (pid, fixture["k"], challenge, proof[:-1])):
            with self.subTest(k=args[1]), self.assertRaises(ValueError):
                candidate.storage.verify_space(*args)

    def test_genuine_native_candidate_rejects_owner_k_challenge_and_plot_transplants(self):
        fixture = self.bound_fixture()
        owner = candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(fixture["owner_seed"]))
        beacon_key = candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(fixture["beacon_seed"]))
        other = candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(b"o" * 32)
        for altered_challenge in (False, True):
            challenge = "0" * 64 if altered_challenge else fixture["challenge"]
            lab = candidate.Rehearsal(fixture["chain"], fixture["beacon_public_key"], {1: challenge})
            signed = registration(lab, owner, bytes.fromhex(fixture["nonce"]), fixture["k"])
            for key, k in ((other, fixture["k"]), (owner, fixture["k"] + 1)):
                mismatch = registration(lab, key, bytes.fromhex(fixture["nonce"]), k)
                mismatch["body"]["plot_id"] = fixture["plot_id"]
                mismatch = candidate.sign(key, mismatch["body"], "registration")
                with self.assertRaisesRegex(ValueError, "identity"):
                    lab.register_plot(mismatch)
            pid = lab.register_plot(signed)
            lab.accept_beacon(beacon(lab, beacon_key, 1))
            body = {"version": 3, "chain": fixture["chain"], "genesis": lab.genesis,
                    "parent": lab.genesis, "height": 1, "round": 1, "owner": fixture["owner_public_key"],
                    "sequence": 0, "plot_id": pid, "proof": fixture["proof"]}
            if altered_challenge:
                with self.assertRaises(ValueError):
                    lab.add_checkpoint(candidate.sign(owner, body, "checkpoint"))
                self.assertEqual(lab.info()["retained_checkpoints"], 0)
            else:
                # A different correctly bound registration cannot reuse another
                # plot's real witness, even when both registrations are signed.
                other_pid = lab.register_plot(registration(lab, owner, b"x" * 32, fixture["k"]))
                transplant = body.copy()
                transplant["plot_id"] = other_pid
                with self.assertRaises(ValueError):
                    lab.add_checkpoint(candidate.sign(owner, transplant, "checkpoint"))
                transplant = body.copy()
                transplant["owner"] = candidate.protocol.public_hex(other)
                with self.assertRaisesRegex(ValueError, "owner"):
                    lab.add_checkpoint(candidate.sign(other, transplant, "checkpoint"))
                self.assertEqual(lab.info()["retained_checkpoints"], 0)
                lab.add_checkpoint(candidate.sign(owner, body, "checkpoint"))

    def test_invalid_native_proof_at_capacity_preserves_the_complete_valid_dag(self):
        fixture = self.bound_fixture()
        owner = candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(fixture["owner_seed"]))
        beacon_key = candidate.protocol.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(fixture["beacon_seed"]))
        lab = candidate.Rehearsal(fixture["chain"], fixture["beacon_public_key"], {1: fixture["challenge"]}, max_checkpoints=1)
        pid = lab.register_plot(registration(lab, owner, bytes.fromhex(fixture["nonce"]), fixture["k"]))
        lab.accept_beacon(beacon(lab, beacon_key, 1))
        body = {"version": 3, "chain": fixture["chain"], "genesis": lab.genesis, "parent": lab.genesis,
                "height": 1, "round": 1, "owner": fixture["owner_public_key"], "sequence": 0,
                "plot_id": pid, "proof": fixture["proof"]}
        original = lab.add_checkpoint(candidate.sign(owner, body, "checkpoint"))
        body["proof"] = "00" * (fixture["k"] * 8)
        with self.assertRaisesRegex(ValueError, "proof"):
            lab.add_checkpoint(candidate.sign(owner, body, "checkpoint"))
        self.assertTrue(lab.info()["evaluation_complete"])
        self.assertEqual(lab.best, original)


if __name__ == "__main__":
    unittest.main()
