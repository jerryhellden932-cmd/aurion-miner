#!/usr/bin/env python3
"""Read-only monitoring. A reachable seed is not evidence of operator independence."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
COIN_SOURCE = ROOT / "coin/aurion.py"
if not COIN_SOURCE.is_file():
    COIN_SOURCE = Path(__file__).resolve().parent / "aurion.py"
spec = importlib.util.spec_from_file_location("aurion_health", COIN_SOURCE)
coin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coin)


def inspect(peers, genesis, stale_seconds=600):
    observations = []
    for peer in peers:
        try:
            info = coin.http_json(peer, "/info", timeout=10)
            if (info.get("genesis") != genesis or type(info.get("height")) is not int
                    or not isinstance(info.get("best"), str) or not coin.HEX64_RE.fullmatch(info["best"])):
                raise ValueError("wrong identity or invalid status")
            checkpoint_time = info.get("checkpoint_time")
            age = max(0, int(time.time()) - checkpoint_time) if type(checkpoint_time) is int else None
            observations.append({"peer": peer, "reachable": True, "height": info["height"],
                                 "best": info["best"], "checkpoint_age_seconds": age,
                                 "progress_fresh": age is not None and age <= stale_seconds})
        except Exception as exc:
            observations.append({"peer": peer, "reachable": False, "error": type(exc).__name__})
    tips = {(o["height"], o["best"]) for o in observations if o["reachable"]}
    healthy = bool(observations) and all(o.get("progress_fresh", False) for o in observations) and len(tips) == 1
    return {"observed_at": int(time.time()), "healthy": healthy, "observations": observations,
            "tip_agreement": len(tips) == 1 and len(tips) > 0,
            "independent_operators_verified": False, "real_funds_ready": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", action="append", required=True)
    parser.add_argument("--genesis", required=True)
    parser.add_argument("--stale-seconds", type=int, default=600)
    args = parser.parse_args()
    if len(args.peer) > 64 or args.stale_seconds <= 0 or not coin.HEX64_RE.fullmatch(args.genesis):
        parser.error("invalid peer count, genesis or freshness threshold")
    result = inspect(args.peer, args.genesis, args.stale_seconds)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["healthy"] else 1)
