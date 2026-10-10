"""Proof-of-space verifier candidate; not an Aurion consensus replacement.

Small plots are permitted only in the explicit local devnet harness. Challenge
generation, time/space tradeoffs, plot eligibility and fork weight need review.
"""
import hashlib
import re


def plot_identity(chain, owner_public_key, nonce, k):
    if not re.fullmatch(r"aurion-upgrade-devnet:[a-z0-9-]{1,48}", chain):
        raise ValueError("only isolated upgrade devnets are supported")
    if not isinstance(owner_public_key, bytes) or len(owner_public_key) != 1952:
        raise ValueError("ML-DSA-65 owner key required")
    if not isinstance(nonce, bytes) or len(nonce) != 32 or type(k) is not int or not 18 <= k <= 50:
        raise ValueError("invalid plot parameters")
    return hashlib.sha256(b"Aurion/v3/devnet/plot\x00" + bytes([len(chain)]) + chain.encode("ascii")
                          + owner_public_key + nonce + bytes([k])).digest()


def verify_space(plot_id, k, challenge, proof):
    """Return the native verifier's quality, or reject. No custom proof fallback."""
    if (not isinstance(plot_id, bytes) or len(plot_id) != 32
            or not isinstance(challenge, bytes) or len(challenge) != 32
            or type(k) is not int or not 18 <= k <= 50
            or not isinstance(proof, bytes) or len(proof) != 8 * k):
        raise ValueError("invalid proof encoding")
    from chiapos import Verifier
    quality = Verifier().validate_proof(plot_id, k, challenge, proof)
    if quality is None or len(quality) != 32:
        raise ValueError("invalid proof of space")
    return bytes(quality)
