#!/usr/bin/env python3
"""Private, noncustodial HTTP adapter for experimental Aurion nodes (stdlib only)."""
import argparse
import hashlib
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

ADDRESS = re.compile(r"aur[0-9a-f]{64}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
UINT = re.compile(r"(?:0|[1-9][0-9]*)\Z")
ZERO = "0" * 64
MAX_BODY = 64_000
MAX_RESPONSE = 8_000_000
TX_KEYS = {"net", "type", "from", "to", "amount", "fee", "idx", "parents", "time", "data"}
DATA_KEYS = {"transfer": set(), "register_plot": {"plot_id", "owner", "nonce", "n", "pow"},
             "htlc_lock": {"hashlock", "timeout"}, "htlc_claim": {"contract", "preimage"},
             "htlc_refund": {"contract"}}


def identifier(kind, envelope):
    encoded = json.dumps(envelope["body"], sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha3_256(kind + encoded).hexdigest()


def api_transaction(tx):
    """Render monetary fields exactly, without changing signature semantics."""
    tx = json.loads(json.dumps(tx))
    for name in ("amount", "fee"):
        value = tx["body"][name]
        if type(value) is not int or value < 0:
            raise APIError(502, "invalid upstream monetary value")
        tx["body"][name] = str(value)
    return tx


def wire_transaction(tx):
    """Convert API decimal unit strings to the signed node's integer encoding."""
    if not isinstance(tx, dict) or set(tx) != {"body", "sig"}:
        raise APIError(400, "expected a signed transaction envelope with body and sig only")
    tx = json.loads(json.dumps(tx))
    body = tx["body"]
    if not isinstance(body, dict) or set(body) != TX_KEYS:
        raise APIError(400, "invalid transaction fields; private keys are never accepted")
    if not isinstance(tx["sig"], str) or not tx["sig"] or len(tx["sig"]) > 20_000:
        raise APIError(400, "a nonempty signature is required")
    for name in ("amount", "fee"):
        value = body[name]
        if not isinstance(value, str) or not UINT.fullmatch(value) or len(value) > 19:
            raise APIError(400, name + " must be a decimal integer string of base units")
        body[name] = int(value)
        if body[name] >= 2 ** 63:
            raise APIError(400, name + " is out of range")
    for name in ("idx", "time"):
        if type(body[name]) is not int or not 0 <= body[name] < 2 ** 63:
            raise APIError(400, "invalid " + name)
    if not isinstance(body["from"], str) or not ADDRESS.fullmatch(body["from"]):
        raise APIError(400, "invalid sender address")
    if not isinstance(body["net"], str):
        raise APIError(400, "invalid network")
    if not isinstance(body["parents"], list) or not 1 <= len(body["parents"]) <= 2 or not all(
            isinstance(x, str) and HASH.fullmatch(x) for x in body["parents"]):
        raise APIError(400, "invalid parents")
    if not isinstance(body["type"], str) or body["type"] not in DATA_KEYS or not isinstance(
            body["data"], dict) or set(body["data"]) != DATA_KEYS[body["type"]]:
        raise APIError(400, "invalid transaction type or data fields")
    return tx


class APIError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Upstream:
    def __init__(self, base="http://127.0.0.1:17333", timeout=15):
        parsed = urlparse(base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("upstream must be an HTTP(S) URL without credentials")
        self.base, self.timeout = base.rstrip("/"), timeout

    def request(self, path, obj=None, optional=False):
        data = None if obj is None else json.dumps(obj).encode()
        req = Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE + 1)
        except HTTPError as exc:
            if optional and exc.code == 404:
                return None
            # Node rejects are meaningful; do not leak upstream internals to clients.
            raise APIError(422 if obj is not None and exc.code == 400 else 502,
                           "upstream rejected the request" if exc.code == 400 else "upstream unavailable") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise APIError(502, "upstream unavailable") from exc
        if len(raw) > MAX_RESPONSE:
            raise APIError(502, "upstream response exceeds adapter limit")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise APIError(502, "invalid upstream JSON") from exc


class ExchangeAPI:
    def __init__(self, upstream, network=None, genesis=None, max_dag_nodes=20_000):
        self.upstream = upstream
        self.expected_network, self.expected_genesis = network, genesis
        self.max_dag_nodes = max_dag_nodes

    def snapshot(self):
        info = self.upstream.request("/info")
        if not isinstance(info, dict) or not isinstance(info.get("network"), str) or not HASH.fullmatch(
                str(info.get("genesis", ""))) or not HASH.fullmatch(str(info.get("best", ""))) or type(
                info.get("height")) is not int or info["height"] < 0:
            raise APIError(502, "invalid upstream network info")
        if self.expected_network and info["network"] != self.expected_network:
            raise APIError(409, "upstream network does not match configured pin")
        if self.expected_genesis and info["genesis"] != self.expected_genesis:
            raise APIError(409, "upstream genesis does not match configured pin")
        return info

    def identity(self, info):
        return {"network": info["network"], "genesis_hash": info["genesis"],
                "network_fingerprint": hashlib.sha3_256((info["network"] + ":" + info["genesis"]).encode()).hexdigest(),
                "tip_hash": info["best"], "tip_height": info["height"], "experimental": True,
                "real_money_deposits_enabled": False}

    def stable(self, original):
        latest = self.snapshot()
        if (latest["height"], latest["best"], latest["genesis"], latest["network"]) != (
                original["height"], original["best"], original["genesis"], original["network"]):
            raise APIError(409, "canonical tip changed during request; retry")

    @staticmethod
    def bounds(query):
        def value(name, default, maximum):
            values = query.get(name, [str(default)])
            if len(values) != 1 or not UINT.fullmatch(values[0]) or len(values[0]) > 10:
                raise APIError(400, "invalid " + name)
            n = int(values[0])
            if n < 1 or n > maximum:
                raise APIError(400, name + " out of range")
            return n
        return value("from", 1, 2 ** 31 - 1), value("limit", 500, 500)

    def checkpoints(self, info, start, limit):
        raw = self.upstream.request("/chain?from=" + str(start))
        cps = raw.get("checkpoints") if isinstance(raw, dict) else None
        if not isinstance(cps, list):
            raise APIError(502, "invalid upstream chain response")
        cps = cps[:limit]
        count = min(limit, max(0, info["height"] - start + 1))
        if len(cps) != count:
            raise APIError(409, "chain length changed or upstream chain is incomplete; retry")
        previous = info["genesis"]
        if cps and start > 1:
            parent = self.upstream.request("/chain?from=" + str(start - 1)).get("checkpoints", [])
            if not parent or parent[0].get("body", {}).get("height") != start - 1:
                raise APIError(502, "missing upstream anchor checkpoint")
            previous = identifier(b"CP", parent[0])
        result = []
        for height, cp in enumerate(cps, start):
            body = cp.get("body", {}) if isinstance(cp, dict) else {}
            if body.get("height") != height or body.get("net") != info["network"] or body.get("prev") != previous:
                raise APIError(502, "upstream checkpoint chain does not match anchor")
            previous = identifier(b"CP", cp)
            result.append({"hash": previous, "height": height, "previous_hash": body["prev"], "checkpoint": cp})
        if result and result[-1]["height"] == info["height"] and previous != info["best"]:
            raise APIError(409, "canonical tip changed during chain read; retry")
        return result

    def transaction(self, txid, query, info):
        start, limit = self.bounds(query)
        tx_response = self.upstream.request("/tx/" + txid, optional=True)
        tx = tx_response.get("tx") if tx_response else None
        if tx is not None and identifier(b"TX", tx) != txid:
            raise APIError(502, "upstream transaction identifier mismatch")
        receipt = self.upstream.request("/receipt/" + txid, optional=True)
        verified = False
        applied = None
        inclusion = None
        if receipt and receipt.get("status") in ("applied", "rejected"):
            h = receipt.get("height")
            if receipt.get("canonical_best") != info["best"] or receipt.get("canonical_height") != info["height"]:
                raise APIError(409, "receipt canonical tip changed; retry")
            if type(h) is not int or h < 1 or h > info["height"] or receipt.get("txid") != txid:
                raise APIError(502, "invalid upstream receipt")
            anchor = self.checkpoints(info, h, 1)
            if anchor[0]["hash"] != receipt.get("checkpoint_hash") or receipt.get("applied") is not (
                    receipt["status"] == "applied"):
                raise APIError(502, "upstream receipt does not match canonical checkpoint")
            verified, applied = True, receipt["applied"]
            inclusion = {"checkpoint_hash": receipt["checkpoint_hash"], "height": h,
                         "source": "canonical_execution_receipt"}

        cps = self.checkpoints(info, start, limit)
        visited, missing, cache = set(), set(), {}
        if tx is not None:
            cache[txid] = tx
        exhausted = False
        reference = None
        for cp in cps:
            stack = list(cp["checkpoint"]["body"].get("tips", []))
            local_seen = set()
            while stack:
                tid = stack.pop()
                if tid == ZERO or tid in local_seen:
                    continue
                if not isinstance(tid, str) or not HASH.fullmatch(tid):
                    raise APIError(502, "invalid upstream transaction reference")
                local_seen.add(tid)
                if tid == txid and reference is None:
                    reference = {"checkpoint_hash": cp["hash"], "height": cp["height"], "source": "dag_reference"}
                if tid in visited:
                    continue
                if len(visited) >= self.max_dag_nodes:
                    exhausted = True
                    break
                visited.add(tid)
                if tid not in cache:
                    found = self.upstream.request("/tx/" + tid, optional=True)
                    candidate = found.get("tx") if found else None
                    if candidate is None:
                        missing.add(tid)
                        continue
                    if identifier(b"TX", candidate) != tid:
                        raise APIError(502, "upstream DAG transaction identifier mismatch")
                    cache[tid] = candidate
                stack.extend(cache[tid]["body"].get("parents", []))
            if exhausted:
                break
        scan_to = cps[-1]["height"] if cps else None
        complete = not exhausted and not missing
        state = ("applied" if applied else "rejected") if verified else (
            "canonical_reference" if reference else "unknown")
        if inclusion is None:
            inclusion = reference
        self.stable(info)
        return {**self.identity(info), "txid": txid, "status": state, "known_to_node": tx is not None,
                "transaction": api_transaction(tx) if tx else None, "inclusion": inclusion,
                "confirmations": info["height"] - inclusion["height"] + 1 if inclusion else None,
                "application_verified": verified, "applied": applied, "finality": "unproven",
                "deposit_eligible": False,
                "scan": {"from": start, "to": scan_to, "requested_limit": limit,
                         "references_complete": complete, "dag_nodes_visited": len(visited),
                         "missing_transactions": sorted(missing), "dag_limit_reached": exhausted,
                         "covers_entire_canonical_chain": start == 1 and scan_to == info["height"] and complete}}

    def handle(self, method, target, body=None):
        parsed = urlparse(target)
        path, query = parsed.path, parse_qs(parsed.query, keep_blank_values=True)
        if method == "GET" and path == "/v1/network":
            info = self.snapshot()
            for name in ("minted", "founder_allocation"):
                if type(info.get(name, 0)) is not int or info.get(name, 0) < 0:
                    raise APIError(502, "invalid upstream monetary value")
            return 200, {**self.identity(info), "node_version": info.get("version"), "asset": "AUR",
                         "decimals": 8, "base_units_per_aur": "100000000", "max_supply_units": "2100000000000000",
                         "minted_units": str(info.get("minted", 0)),
                         "founder_allocation_units": str(info.get("founder_allocation", 0)),
                         "configured_pins": bool(self.expected_network and self.expected_genesis),
                         "finality": "unproven"}
        if method == "GET" and path.startswith("/v1/addresses/"):
            address = path[len("/v1/addresses/"):]
            if not ADDRESS.fullmatch(address):
                raise APIError(400, "invalid Aurion address")
            info = self.snapshot()
            account = self.upstream.request("/account/" + address)
            if account.get("height") != info["height"]:
                raise APIError(409, "account canonical height changed; retry")
            balances = {}
            for name in ("balance", "locked", "spendable"):
                if type(account.get(name)) is not int or account[name] < 0:
                    raise APIError(502, "invalid upstream account balance")
                balances[name + "_units"] = str(account[name])
            self.stable(info)
            return 200, {**self.identity(info), "address": address, **balances,
                         "last_signature_index": account.get("last_idx"), "signature_capacity": 1024}
        if method == "GET" and path == "/v1/checkpoints":
            start, limit = self.bounds(query)
            info = self.snapshot()
            cps = self.checkpoints(info, start, limit)
            self.stable(info)
            next_height = cps[-1]["height"] + 1 if cps and cps[-1]["height"] < info["height"] else None
            return 200, {**self.identity(info), "checkpoints": cps, "from": start, "limit": limit,
                         "next_from": next_height, "execution_receipts_included": False}
        if method == "GET" and path.startswith("/v1/transactions/"):
            txid = path[len("/v1/transactions/"):]
            if not HASH.fullmatch(txid):
                raise APIError(400, "invalid transaction identifier")
            return 200, self.transaction(txid, query, self.snapshot())
        if method == "POST" and path == "/v1/transactions":
            if not self.expected_network or not self.expected_genesis:
                raise APIError(409, "broadcast requires configured network and genesis pins")
            info = self.snapshot()
            tx = wire_transaction(body)
            if tx["body"]["net"] != info["network"]:
                raise APIError(400, "transaction targets a different network")
            txid = identifier(b"TX", tx)
            response = self.upstream.request("/tx", tx)
            if response.get("status") not in ("ok", "dup"):
                raise APIError(422, "transaction not accepted by node")
            self.stable(info)
            return 202, {**self.identity(info), "txid": txid, "broadcast_status": response["status"],
                         "application_verified": False, "deposit_eligible": False,
                         "message": "Accepted by node; execution and canonical inclusion are not established."}
        raise APIError(404, "endpoint not found")


def make_handler(api):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self, status, value):
            encoded = json.dumps(value, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def dispatch(self):
            try:
                body = None
                if self.command == "POST":
                    if self.headers.get("Transfer-Encoding"):
                        raise APIError(400, "chunked requests are not supported")
                    content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
                    if content_type != "application/json":
                        raise APIError(415, "Content-Type must be application/json")
                    length = self.headers.get("Content-Length", "")
                    if not UINT.fullmatch(length):
                        raise APIError(400, "valid Content-Length is required")
                    size = int(length)
                    if size > MAX_BODY:
                        raise APIError(413, "request too large")
                    body = json.loads(self.rfile.read(size))
                status, value = api.handle(self.command, self.path, body)
                self.respond(status, value)
            except APIError as exc:
                self.respond(exc.status, {"error": str(exc), "experimental": True})
            except (ValueError, UnicodeError):
                self.respond(400, {"error": "invalid JSON request", "experimental": True})
            except Exception:
                self.respond(502, {"error": "invalid or unavailable upstream response", "experimental": True})

        do_GET = dispatch
        do_POST = dispatch
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", default="http://127.0.0.1:17333")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=17334)
    parser.add_argument("--network", help="pin exact /info network name")
    parser.add_argument("--genesis", help="pin exact genesis checkpoint hash")
    args = parser.parse_args()
    if args.genesis and not HASH.fullmatch(args.genesis):
        parser.error("--genesis must be a 64-character lowercase hash")
    api = ExchangeAPI(Upstream(args.upstream), args.network, args.genesis)
    api.snapshot()
    server = ThreadingHTTPServer((args.bind, args.port), make_handler(api))
    print("Experimental Aurion exchange adapter: http://%s:%d (no real-money deposits)" % (args.bind, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
