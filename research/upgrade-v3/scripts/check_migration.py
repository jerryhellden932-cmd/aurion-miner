#!/usr/bin/env python3
"""Compile/verify public v1 preservation evidence offline; never migrate funds.

Required hashes and checkpoint must come from separately retained operator
records, not fields copied unquestioningly from the supplied backup. Supports
only aurion-hosted-public-ledger-backup v1, not active SQLite files or wallets.
Source code must be reviewed before its SHA256 is pinned. This is not a sandbox.
Output is a new mode-0600 file; existing files and symlink paths are rejected.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from upgrade import preservation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--coin-source", required=True)
    parser.add_argument("--network", choices=("mainnet", "testnet", "regtest"), required=True)
    parser.add_argument("--genesis", required=True)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--ledger-sha256", required=True)
    parser.add_argument("--coin-sha256", required=True)
    parser.add_argument("--founder", help="testnet/regtest genesis only")
    parser.add_argument("--candidate", help="verify this packet by full rederivation instead of compiling")
    parser.add_argument("--output", required=True, help="new output file in an existing directory")
    args = parser.parse_args(argv)
    inputs = [args.ledger, args.coin_source] + ([args.candidate] if args.candidate else [])
    try:
        output = preservation.path_without_symlinks(args.output)
        if output.exists() or output in {preservation.path_without_symlinks(item) for item in inputs}:
            raise ValueError("output must be new and differ from every input")
        packet = preservation.compile_packet(args.ledger, args.coin_source, network=args.network,
                    genesis=args.genesis, checkpoint=args.checkpoint, ledger_sha256=args.ledger_sha256,
                    coin_sha256=args.coin_sha256, founder=args.founder)
        result = preservation.verify_candidate(args.candidate, packet) if args.candidate else packet
        preservation.write_exclusive(output, result, inputs)
        print(json.dumps({"output": str(output), "packet_sha256": packet["packet_sha256"],
                          "height": packet["replay"]["height"], **preservation.SAFETY}, sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError, KeyError, SyntaxError) as exc:
        print(json.dumps({"error": str(exc), **preservation.SAFETY}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
