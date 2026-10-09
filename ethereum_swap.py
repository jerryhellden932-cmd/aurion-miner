#!/usr/bin/env python3
"""Build unsigned AurionHTLC transactions and read Ethereum mainnet state.

This tool never imports private keys, signs, sends ETH, or broadcasts a transaction.
An external Ethereum wallet must approve transactions and pay gas.
"""
import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SELECTORS = {
    "lock(address,bytes32,uint64)": "473500ff",
    "claim(bytes32,bytes32)": "84cc9dfb",
    "refund(bytes32)": "7249fbb6",
    "swaps(bytes32)": "eb84e7f2",
}
LOCKED_TOPIC = "0xc6c914be2236b5d609b6fd70ffc78fc66d2ac639528c3cbd03eee0e7eccb9192"
ZERO_ADDRESS = "0x" + "0" * 40


def address(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value) or value.lower() == ZERO_ADDRESS:
        raise ValueError("Expected a nonzero Ethereum address")
    return value.lower()


def bytes32(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", value):
        raise ValueError("Expected exactly 32 bytes of hexadecimal")
    return value.removeprefix("0x").lower()


def ether_to_wei(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.\d{1,18})?", value):
        raise ValueError("ETH amount must be an exact decimal string with at most 18 decimal places")
    whole, _, fraction = value.partition(".")
    wei = int(whole) * 10 ** 18 + int(fraction.ljust(18, "0"))
    if not 0 < wei < 2 ** 256:
        raise ValueError("ETH amount is outside the uint256 range")
    return wei


def encode_lock(recipient, hashlock, expires_at):
    expires_at = int(expires_at)
    if not 0 < expires_at < 2 ** 64:
        raise ValueError("Deadline must be a positive uint64 Unix timestamp")
    commitment = bytes32(hashlock)
    if int(commitment, 16) == 0:
        raise ValueError("Hashlock cannot be zero")
    return "0x" + SELECTORS["lock(address,bytes32,uint64)"] + address(recipient)[2:].rjust(64, "0") + commitment + f"{expires_at:064x}"


def encode_claim(swap_id, preimage):
    return "0x" + SELECTORS["claim(bytes32,bytes32)"] + bytes32(swap_id) + bytes32(preimage)


def encode_refund(swap_id):
    return "0x" + SELECTORS["refund(bytes32)"] + bytes32(swap_id)


def decode_swap(encoded):
    if not isinstance(encoded, str) or not re.fullmatch(r"0x[0-9a-fA-F]{384}", encoded):
        raise ValueError("Malformed Ethereum swap result")
    words = [encoded[i:i + 64] for i in range(2, len(encoded), 64)]
    state = int(words[5], 16)
    if state not in range(4) or not words[0].startswith("0" * 24) or not words[1].startswith("0" * 24):
        raise ValueError("Malformed Ethereum swap state")
    return {"sender": "0x" + words[0][24:].lower(), "recipient": "0x" + words[1][24:].lower(),
            "hashlock": "0x" + words[2].lower(), "expiresAt": str(int(words[3], 16)),
            "amountWei": str(int(words[4], 16)), "state": state,
            "status": ("unknown", "open", "claimed", "refunded")[state]}


def load_artifact(path):
    if path is None:
        candidates = [Path(__file__).resolve().parent.parent / "docs" / "AurionHTLC.artifact.json",
                      Path(__file__).resolve().parent / "AurionHTLC.artifact.json"]
        path = next((candidate for candidate in candidates if candidate.is_file()), candidates[0])
    artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    if artifact.get("contractName") != "AurionHTLC":
        raise ValueError("Unexpected contract artifact")
    for key in ("bytecode", "deployedBytecode"):
        if not re.fullmatch(r"0x[0-9a-fA-F]+", artifact.get(key, "")):
            raise ValueError("Artifact does not contain compiled bytecode")
    for signature, selector in SELECTORS.items():
        if artifact.get("methodIdentifiers", {}).get(signature) != selector:
            raise ValueError("Artifact selector mismatch")
    return artifact


class EthereumRPC:
    def __init__(self, url):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("https", "http") or not parsed.hostname:
            raise ValueError("RPC URL must use HTTP or HTTPS")
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("Use HTTPS for remote Ethereum RPC endpoints")
        self.url = url
        self.sequence = 0

    def call(self, method, params=None):
        self.sequence += 1
        payload = {"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params or []}
        request = urllib.request.Request(self.url, json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": "Aurion-Ethereum/0.2.0"})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
        except (urllib.error.URLError, OSError) as error:
            raise ValueError("Ethereum RPC request failed; check endpoint connectivity") from error
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("Ethereum RPC response exceeded the size limit")
        response = json.loads(raw)
        if response.get("id") != self.sequence or response.get("jsonrpc") != "2.0":
            raise ValueError("Invalid Ethereum RPC response")
        if response.get("error"):
            raise ValueError("Ethereum RPC returned an error (code %s)" % response["error"].get("code", "unknown"))
        if "result" not in response:
            raise ValueError("Ethereum RPC response has no result")
        return response["result"]

    def mainnet(self):
        if int(self.call("eth_chainId"), 16) != 1:
            raise ValueError("RPC endpoint must connect to Ethereum mainnet, chain ID 1")

    def verify_contract(self, contract, artifact):
        self.mainnet()
        target = address(contract)
        actual = self.call("eth_getCode", [target, "latest"])
        if not isinstance(actual, str) or actual.lower() != artifact["deployedBytecode"].lower():
            raise ValueError("Contract runtime does not match the supplied artifact")
        return target


def unsigned(sender, data, contract=None, wei=0):
    transaction = {"from": address(sender), "chainId": "0x1", "data": data, "value": hex(wei)}
    if contract is not None:
        transaction["to"] = address(contract)
    return transaction


def parser():
    cli = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    cli.add_argument("--artifact", help="Compiled AurionHTLC artifact path")
    sub = cli.add_subparsers(dest="command", required=True)
    deploy = sub.add_parser("deploy", help="Build an unsigned native-ETH contract deployment")
    deploy.add_argument("--sender", required=True)
    lock = sub.add_parser("lock", help="Build an unsigned native-ETH lock transaction")
    lock.add_argument("--sender", required=True)
    lock.add_argument("--contract", required=True)
    lock.add_argument("--recipient", required=True)
    lock.add_argument("--hash", required=True, dest="hashlock")
    lock.add_argument("--expires-at", required=True, type=int, help="Absolute Unix deadline, at most 30 days ahead")
    lock.add_argument("--eth", required=True, help="Exact ETH decimal amount")
    for command in ("claim", "refund"):
        action = sub.add_parser(command, help="Build an unsigned ETH %s transaction" % command)
        action.add_argument("--sender", required=True)
        action.add_argument("--contract", required=True)
        action.add_argument("--id", required=True, dest="swap_id")
        if command == "claim":
            action.add_argument("--preimage", required=True, help="32-byte secret; disclosure settles the hashlock")
    state = sub.add_parser("status", help="Read an ETH lock from a bytecode-verified contract")
    state.add_argument("--rpc", required=True)
    state.add_argument("--contract", required=True)
    state.add_argument("--id", required=True, dest="swap_id")
    receipt = sub.add_parser("receipt", help="Read a settlement or deployment transaction receipt")
    receipt.add_argument("--rpc", required=True)
    receipt.add_argument("--tx", required=True)
    receipt.add_argument("--contract", help="Expected settlement contract; omit for deployment")
    secret = sub.add_parser("hash", help="Compute the SHA-256 commitment for a supplied 32-byte secret")
    secret.add_argument("--preimage", required=True)
    return cli


def execute(args):
    if args.command == "hash":
        return {"hashlock": "0x" + hashlib.sha256(bytes.fromhex(bytes32(args.preimage))).hexdigest()}
    compiled = load_artifact(args.artifact)
    if args.command == "deploy":
        tx = unsigned(args.sender, compiled["bytecode"])
    elif args.command == "lock":
        if not int(time.time()) < args.expires_at <= int(time.time()) + 30 * 86400:
            raise ValueError("ETH deadline must be in the future and within 30 days")
        if address(args.recipient) == address(args.contract):
            raise ValueError("Contract cannot be its own recipient")
        tx = unsigned(args.sender, encode_lock(args.recipient, args.hashlock, args.expires_at), args.contract, ether_to_wei(args.eth))
    elif args.command == "claim":
        tx = unsigned(args.sender, encode_claim(args.swap_id, args.preimage), args.contract)
    elif args.command == "refund":
        tx = unsigned(args.sender, encode_refund(args.swap_id), args.contract)
    elif args.command == "status":
        rpc = EthereumRPC(args.rpc)
        target = rpc.verify_contract(args.contract, compiled)
        data = "0x" + SELECTORS["swaps(bytes32)"] + bytes32(args.swap_id)
        return decode_swap(rpc.call("eth_call", [{"to": target, "data": data}, "latest"]))
    elif args.command == "receipt":
        rpc = EthereumRPC(args.rpc)
        rpc.mainnet()
        receipt = rpc.call("eth_getTransactionReceipt", ["0x" + bytes32(args.tx)])
        if receipt is None:
            return {"status": "pending"}
        if int(receipt["status"], 16) != 1:
            raise ValueError("Ethereum transaction reverted")
        if args.contract:
            target = rpc.verify_contract(args.contract, compiled)
            if address(receipt.get("to")) != target:
                raise ValueError("Receipt targets another contract")
        else:
            target = rpc.verify_contract(receipt.get("contractAddress"), compiled)
        return {"status": "mined", "verifiedContract": target, "receipt": receipt,
                "finality": "Verify canonical inclusion and finality independently; a mined receipt is not finality."}
    else:
        raise ValueError("Unsupported command")
    return {"transaction": tx, "broadcast": False,
            "next": "Approve this unsigned transaction in an Ethereum mainnet wallet; gas must be funded separately.",
            "contractVerified": False, "warning": "Verify runtime bytecode and swap terms before signing."}


def main():
    try:
        print(json.dumps(execute(parser().parse_args()), indent=2))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("Error: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
