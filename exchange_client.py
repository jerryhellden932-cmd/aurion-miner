#!/usr/bin/env python3
"""Exact-unit, noncustodial Aurion exchange API client (Python stdlib)."""
import argparse
import json
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class ExchangeClient:
    def __init__(self, base="http://127.0.0.1:17334", network=None, genesis=None, timeout=20):
        self.base, self.network, self.genesis, self.timeout = base.rstrip("/"), network, genesis, timeout

    def request(self, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout) as response:
                value = json.loads(response.read())
        except HTTPError as exc:
            raise RuntimeError("Aurion API HTTP %s: %s" % (exc.code, exc.read().decode())) from exc
        if self.network and value.get("network") != self.network:
            raise RuntimeError("network pin mismatch")
        if self.genesis and value.get("genesis_hash") != self.genesis:
            raise RuntimeError("genesis pin mismatch")
        return value

    def network_info(self):
        return self.request("/v1/network")

    def address(self, address):
        return self.request("/v1/addresses/" + address)

    def checkpoints(self, start=1, limit=500):
        return self.request("/v1/checkpoints?" + urlencode({"from": start, "limit": limit}))

    def transaction(self, txid, start=1, limit=500):
        return self.request("/v1/transactions/" + txid + "?" + urlencode({"from": start, "limit": limit}))

    def broadcast(self, signed_transaction):
        # Native node exports use JSON integers; normalize these exact integers to API unit strings.
        envelope = json.loads(json.dumps(signed_transaction))
        for name in ("amount", "fee"):
            value = envelope["body"][name]
            if type(value) is int:
                envelope["body"][name] = str(value)
        return self.request("/v1/transactions", envelope)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:17334")
    parser.add_argument("--network")
    parser.add_argument("--genesis")
    parser.add_argument("command", choices=["network", "address", "checkpoints", "transaction", "broadcast"])
    parser.add_argument("value", nargs="?")
    parser.add_argument("--from", dest="start", type=int, default=1)
    parser.add_argument("--limit", type=int, default=500)
    args = parser.parse_args()
    client = ExchangeClient(args.api, args.network, args.genesis)
    if args.command == "network":
        result = client.network_info()
    elif args.command == "checkpoints":
        result = client.checkpoints(args.start, args.limit)
    else:
        if not args.value:
            parser.error("this command requires an address, transaction identifier or signed JSON file")
        if args.command == "address":
            result = client.address(args.value)
        elif args.command == "transaction":
            result = client.transaction(args.value, args.start, args.limit)
        else:
            with open(args.value, encoding="utf-8") as handle:
                result = client.broadcast(json.load(handle))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
