"""Offline v3 laboratory DAG, NOT a production consensus or activation path.

The authenticated fixture beacon is trusted, predeclared and predictable. Its
rounds are not unbiased randomness. The arbitrary quality-byte scoring rule has
no economic-security analysis. No accounts, payments, migration, finality, peer
protocol or production clock is implemented. Native chiapos is mandatory.
"""
from dataclasses import dataclass, replace
import hashlib
import importlib.metadata
import json
import re

from . import protocol, storage

CHAIN_RE = re.compile(r"aurion-upgrade-devnet:[a-z0-9-]{1,48}")
DOMAINS = {name: ("Aurion/v3/offline-rehearsal/" + name).encode()
           for name in ("registration", "beacon", "checkpoint")}
FIELDS = {
    "registration": {"version", "chain", "genesis", "owner", "nonce", "k", "plot_id"},
    "beacon": {"version", "chain", "genesis", "round", "challenge"},
    "checkpoint": {"version", "chain", "genesis", "parent", "height", "round", "owner", "sequence", "plot_id", "proof"},
}
NOTICE = "Trusted predictable test beacon; arbitrary non-economic lab score; no finality, independent network or real-funds qualification."


class MissingDependency(ValueError):
    pass


class MissingParent(ValueError):
    pass


class IncompleteEvaluation(ValueError):
    pass


def require_native():
    try:
        if importlib.metadata.version("chiapos") != "2.0.12":
            raise MissingDependency("chiapos==2.0.12 is required; no substitute verifier")
        from chiapos import Verifier
        Verifier()
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
        raise MissingDependency("chiapos==2.0.12 is unavailable; no proof fallback") from exc


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def snapshot_body(body, kind):
    if type(body) is not dict or len(body) != len(FIELDS[kind]):
        raise ValueError("invalid " + kind + " fields")
    body = body.copy()
    if set(body) != FIELDS[kind]:
        raise ValueError("invalid " + kind + " fields")
    for value in body.values():
        if type(value) not in (str, int) or (type(value) is str and len(value) > 4000):
            raise ValueError("bounded flat canonical fields required")
        if type(value) is int and not 0 <= value < 2 ** 53:
            raise ValueError("invalid integer field")
    if (type(body["version"]) is not int or body["version"] != 3
            or type(body["chain"]) is not str or not CHAIN_RE.fullmatch(body["chain"])):
        raise ValueError("only isolated v3 rehearsal chains are supported")
    protocol.decode_hex(body["genesis"], 32)
    return body


def snapshot_envelope(envelope, kind):
    if type(envelope) is not dict or len(envelope) != 2:
        raise ValueError("invalid envelope")
    envelope = envelope.copy()
    if set(envelope) != {"body", "signature"}:
        raise ValueError("invalid envelope fields")
    body = snapshot_body(envelope["body"], kind)
    if type(envelope["signature"]) is not str:
        raise ValueError("canonical signature string required")
    protocol.decode_hex(envelope["signature"], protocol.SIGNATURE_BYTES)
    return {"body": body, "signature": envelope["signature"]}


def sign(key, body, kind):
    """Sign a detached fixture body with its distinct laboratory-purpose context."""
    body = snapshot_body(body, kind)
    if kind != "beacon" and body["owner"] != protocol.public_hex(key):
        raise ValueError("signer does not own this fixture body")
    return {"body": body, "signature": key.sign(encoded(body), DOMAINS[kind]).hex()}


def authenticate(envelope, public_key, kind):
    key = protocol.MLDSA65PublicKey.from_public_bytes(protocol.decode_hex(public_key, protocol.PUBLIC_KEY_BYTES))
    try:
        key.verify(protocol.decode_hex(envelope["signature"], protocol.SIGNATURE_BYTES), encoded(envelope["body"]), DOMAINS[kind])
    except protocol.InvalidSignature as exc:
        raise ValueError("invalid ML-DSA " + kind + " signature") from exc


def identifier(body):
    return hashlib.sha3_256(b"Aurion/v3/offline-rehearsal/header\x00" + encoded(body)).hexdigest()


def packet_sha256(packet):
    """Digest an owned export; retain this pin separately before a later replay."""
    return hashlib.sha256(encoded(packet)).hexdigest()


@dataclass(frozen=True)
class Header:
    parent: str
    height: int
    total: int
    sequences: dict
    envelope: bytes | None


class Rehearsal:
    def __init__(self, chain, beacon_public_key, round_challenges, *, max_checkpoints=512, max_plots=32):
        # Reject production domains before importing a native dependency.
        if type(chain) is not str or not CHAIN_RE.fullmatch(chain):
            raise ValueError("mainnet and production chains are not supported")
        if type(beacon_public_key) is not str:
            raise ValueError("pinned canonical fixture beacon key required")
        protocol.decode_hex(beacon_public_key, protocol.PUBLIC_KEY_BYTES)
        if type(round_challenges) is not dict or len(round_challenges) > 2048:
            raise ValueError("bounded predeclared fixture rounds required")
        rounds = round_challenges.copy()
        if not 1 <= len(rounds) <= 2048:
            raise ValueError("bounded predeclared fixture rounds required")
        if any(type(i) is not int for i in rounds) or set(rounds) != set(range(1, len(rounds) + 1)):
            raise ValueError("fixture rounds must be contiguous positive integers")
        for challenge in rounds.values():
            if type(challenge) is not str:
                raise ValueError("canonical fixture challenge required")
            protocol.decode_hex(challenge, 32)
        if len(set(rounds.values())) != len(rounds):
            raise ValueError("fixture challenges must not repeat")
        if (type(max_checkpoints) is not int or not 1 <= max_checkpoints <= 2048
                or type(max_plots) is not int or not 1 <= max_plots <= 128):
            raise ValueError("invalid laboratory resource caps")
        require_native()
        self._configuration = {"chain": chain, "beacon_public_key": beacon_public_key,
            "rounds": [[i, rounds[i]] for i in sorted(rounds)], "max_checkpoints": max_checkpoints,
            "max_plots": max_plots, "rule": "lab-score=1+255-first-quality-byte;max(total,height,header-id)"}
        self._genesis = hashlib.sha3_256(b"Aurion/v3/offline-rehearsal/genesis\x00" + encoded(self._configuration)).hexdigest()
        self._rounds, self._plots, self._beacons = rounds, {}, {}
        self._headers = {self._genesis: Header("", 0, 0, {}, None)}
        self._best, self._complete = self._genesis, True

    @property
    def genesis(self):
        return self._genesis

    @property
    def best(self):
        self._check_complete()
        return self._best

    def _check_complete(self):
        if not self._complete:
            raise IncompleteEvaluation("capacity exceeded; campaign completeness and convergence cannot be claimed")

    def _scope(self, body):
        self._check_complete()
        if body["chain"] != self._configuration["chain"] or body["genesis"] != self._genesis:
            raise ValueError("wrong rehearsal chain or genesis")

    def _capacity(self, size, cap):
        if size >= cap:
            self._complete = False
            raise IncompleteEvaluation("capacity exceeded; history retained, evaluation incomplete")

    def challenge(self, round_number):
        self._check_complete()
        if type(round_number) is not int or round_number not in self._beacons:
            raise ValueError("unknown or unauthenticated fixture round")
        return bytes.fromhex(self._rounds[round_number])

    def register_plot(self, original):
        envelope = snapshot_envelope(original, "registration")
        body = envelope["body"]
        self._scope(body)
        owner = protocol.decode_hex(body["owner"], protocol.PUBLIC_KEY_BYTES)
        nonce = protocol.decode_hex(body["nonce"], 32)
        if body["owner"] == self._configuration["beacon_public_key"]:
            raise ValueError("fixture producer and beacon must use separate keys")
        expected = storage.plot_identity(body["chain"], owner, nonce, body["k"]).hex()
        if body["plot_id"] != expected:
            raise ValueError("plot identity does not bind chain, owner, nonce and k")
        authenticate(envelope, body["owner"], "registration")
        record = encoded(envelope)
        if expected in self._plots:
            self._plots[expected] = min(self._plots[expected], record)
            return expected
        self._capacity(len(self._plots), self._configuration["max_plots"])
        self._plots[expected] = record
        return expected

    def accept_beacon(self, original):
        envelope = snapshot_envelope(original, "beacon")
        body = envelope["body"]
        self._scope(body)
        if type(body["round"]) is not int or self._rounds.get(body["round"]) != body["challenge"]:
            raise ValueError("unknown or equivocated predeclared beacon round")
        authenticate(envelope, self._configuration["beacon_public_key"], "beacon")
        record = encoded(envelope)
        self._beacons[body["round"]] = min(self._beacons.get(body["round"], record), record)
        return body["round"]

    def add_checkpoint(self, original):
        envelope = snapshot_envelope(original, "checkpoint")
        body = envelope["body"]
        self._scope(body)
        protocol.decode_hex(body["parent"], 32)
        parent = self._headers.get(body["parent"])
        if parent is None:
            # No arrival-pruned graph or persistent orphan queue. The bounded
            # offline caller may resubmit after supplying dependencies.
            raise MissingParent("unknown parent; supply it and resubmit")
        if (type(body["height"]) is not int or body["height"] != parent.height + 1
                or type(body["round"]) is not int or body["round"] != body["height"]):
            raise ValueError("parent/height/fixture-round mismatch")
        challenge = self.challenge(body["round"])
        protocol.decode_hex(body["owner"], protocol.PUBLIC_KEY_BYTES)
        registration = self._plots.get(body["plot_id"])
        if registration is None:
            raise ValueError("unknown plot; supply its registration and resubmit")
        plot = json.loads(registration)["body"]
        if body["owner"] != plot["owner"]:
            raise ValueError("plot owner mismatch")
        if type(body["sequence"]) is not int or body["sequence"] != parent.sequences.get(body["owner"], 0):
            raise ValueError("wrong branch-local owner sequence")
        proof = protocol.decode_hex(body["proof"], 8 * plot["k"])
        authenticate(envelope, body["owner"], "checkpoint")
        ident, record = identifier(body), encoded(envelope)
        if ident in self._headers:
            old = self._headers[ident]
            self._headers[ident] = replace(old, envelope=min(old.envelope, record))
            return ident
        quality = storage.verify_space(bytes.fromhex(plot["plot_id"]), plot["k"], challenge, proof)
        if type(quality) is not bytes or len(quality) != 32:
            raise ValueError("malformed native quality")
        self._capacity(len(self._headers) - 1, self._configuration["max_checkpoints"])
        # Deliberately arbitrary bounded laboratory score, not a difficulty,
        # resource-majority, timing, compression or economic-security model.
        score = 1 + 255 - quality[0]
        sequences = parent.sequences.copy()
        sequences[body["owner"]] = body["sequence"] + 1
        self._headers[ident] = Header(body["parent"], body["height"], parent.total + score, sequences, record)
        self._best = max(self._headers, key=lambda i: (self._headers[i].total, self._headers[i].height, i))
        return ident

    def info(self):
        tip = self._headers[self._best]
        return {"genesis": self._genesis, "best": self._best if self._complete else None,
                "height": tip.height if self._complete else None, "laboratory_weight": tip.total if self._complete else None,
                "retained_checkpoints": len(self._headers) - 1, "evaluation_complete": self._complete,
                "evaluation_complete_scope": "No overflow of supplied accepted records; not proof all campaign or network inputs were delivered.",
                "real_funds_ready": False, "security_certification": False, "activation_authorized": False,
                "independent_network_verified": False, "unbiased_randomness_verified": False,
                "proof_of_space_verified": False, "notice": NOTICE,
                "proof_note": "Native verification is mandatory in unpatched execution; this metadata makes no attested proof/security claim. Mocked test models are not native verification evidence."}

    def export(self):
        """Detached exact signed representatives for replay with external pins."""
        return {"schema_version": 1, "configuration": json.loads(encoded(self._configuration)),
                "genesis": self._genesis, "best": self._best if self._complete else None, "evaluation_complete": self._complete,
                "proof_of_space_verified": False,
                "registrations": [json.loads(self._plots[i]) for i in sorted(self._plots)],
                "beacons": [json.loads(self._beacons[i]) for i in sorted(self._beacons)],
                "checkpoints": [json.loads(record.envelope) for ident, record in sorted(
                    self._headers.items(), key=lambda item: (item[1].height, item[0])) if record.envelope is not None],
                "notice": NOTICE}

    @classmethod
    def from_export(cls, original, chain, beacon_public_key, round_challenges, *, expected_packet_sha256, **caps):
        # Bound and detach the only nested input before checking or replaying it.
        budget = [0, 0]
        def copy(value, depth=0):
            budget[0] += 1
            if depth > 5 or budget[0] > 120000:
                raise ValueError("bounded replay packet required")
            if type(value) is dict:
                if len(value) > 32:
                    raise ValueError("replay object exceeds resource bounds")
                value = value.copy()
                if len(value) > 32 or any(type(key) is not str or len(key) > 64 for key in value):
                    raise ValueError("invalid replay object")
                return {key: copy(item, depth + 1) for key, item in value.items()}
            if type(value) is list:
                if len(value) > 2048:
                    raise ValueError("replay list exceeds resource bounds")
                value = value.copy()
                if len(value) > 2048:
                    raise ValueError("replay list exceeds resource bounds")
                return [copy(item, depth + 1) for item in value]
            if type(value) not in (str, int, bool) or (type(value) is str and (len(value) > 7000 or not value.isascii())):
                raise ValueError("invalid replay value")
            budget[1] += len(value) if type(value) is str else 16
            if budget[1] > 64 * 1024 * 1024 or (type(value) is int and not 0 <= value < 2 ** 53):
                raise ValueError("replay byte/value bounds exceeded")
            return value
        packet = copy(original)
        if type(packet) is not dict or set(packet) != {"schema_version", "configuration", "genesis", "best", "evaluation_complete", "proof_of_space_verified", "registrations", "beacons", "checkpoints", "notice"}:
            raise ValueError("invalid replay packet fields")
        if type(expected_packet_sha256) is not str:
            raise ValueError("externally retained canonical packet digest required")
        protocol.decode_hex(expected_packet_sha256, 32)
        if packet_sha256(packet) != expected_packet_sha256:
            raise ValueError("replay packet differs from externally retained digest")
        if (type(packet["schema_version"]) is not int or packet["schema_version"] != 1
                or packet["evaluation_complete"] is not True or packet["proof_of_space_verified"] is not False
                or packet["notice"] != NOTICE):
            raise ValueError("incomplete or mislabelled replay packet")
        lab = cls(chain, beacon_public_key, round_challenges, **caps)
        if encoded(packet["configuration"]) != encoded(lab._configuration) or packet["genesis"] != lab.genesis:
            raise ValueError("replay does not match caller-pinned rehearsal genesis")
        for name in ("registrations", "beacons", "checkpoints"):
            if type(packet[name]) is not list:
                raise ValueError("replay records must be bounded lists")
        for record in packet["registrations"]:
            lab.register_plot(record)
        for record in packet["beacons"]:
            lab.accept_beacon(record)
        for record in packet["checkpoints"]:
            lab.add_checkpoint(record)
        if packet["best"] != lab.best:
            raise ValueError("replayed best header differs from pinned snapshot")
        return lab
