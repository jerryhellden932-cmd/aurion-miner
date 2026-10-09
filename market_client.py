#!/usr/bin/env python3
"""Aurion's hosted offer book: publish offers and accept peer quotes.

Matching reserves an offer; it does not transfer AUR, ETH or BTC. Settlement
requires the separate wallet/HTLC workflow. No liquidity or prices are invented.
Choose both offer amounts to set your own ETH-per-AUR or BTC-per-AUR rate.
Quotes require an actual counterparty and can fill only part of your budget.
Passwords are prompted privately and session cookies exist only in memory.
"""
import argparse
import decimal
import getpass
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings


DEFAULT_SITE = "https://aurioncoin.io"
MAINNET_NETWORK = "aurion-mainnet"
MAINNET_GENESIS = "4f3347fd386cf267163dc329bd9781ef61b2915927507646d31c2584b977000d"
ASSET_DECIMALS = {"AUR": 8, "BTC": 8, "ETH": 18}
MAX_UNITS = {"AUR": 2_100_000_000_000_000, "BTC": 2_100_000_000_000_000,
             "ETH": (1 << 256) - 1}
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
CLI_EXAMPLES = """\
Set your rate by choosing the amount you give and the amount you request:
  --email EMAIL offer create --give AUR --receive ETH --give-amount AUR_AMOUNT --receive-amount ETH_AMOUNT --external-address YOUR_ETH_ADDRESS
  --email EMAIL offer create --give AUR --receive BTC --give-amount AUR_AMOUNT --receive-amount BTC_AMOUNT --external-address YOUR_BTC_ADDRESS
Request an actual matching quote, with your budget and minimum receipt:
  --email EMAIL quote --sell ETH --buy AUR --amount ETH_BUDGET --min-buy MIN_AUR
  --email EMAIL quote --sell BTC --buy AUR --amount BTC_BUDGET --min-buy MIN_AUR
Accept the reviewed quote using your address for its external asset:
  --email EMAIL accept QUOTE_UUID --external-address YOUR_ETH_OR_BTC_ADDRESS
Then open https://aurioncoin.io/trade to find the trade under your activity.
ETH has a guided wallet workflow; BTC requires manual Bitcoin settlement tools.
Acceptance creates an unfunded match. It never confirms a payment or a refund.
"""


class MarketError(Exception):
    """A user-readable error that never includes a password or cookie value."""


def asset_name(value):
    if not isinstance(value, str) or value.upper() not in ASSET_DECIMALS:
        raise ValueError("asset must be AUR, BTC or ETH")
    return value.upper()


def asset_pair(give_asset, receive_asset):
    give, receive = asset_name(give_asset), asset_name(receive_asset)
    if give == receive or (give == "AUR") == (receive == "AUR"):
        raise ValueError("supported pairs are AUR/BTC and AUR/ETH, in either direction")
    return give, receive


def amount_to_units(value, asset):
    """Convert a decimal coin amount to its exact integer-unit string."""
    asset = asset_name(asset)
    if not isinstance(value, (str, decimal.Decimal)) or len(str(value)) > 512:
        raise ValueError("amount must be a decimal string, never a floating-point number")
    try:
        amount = decimal.Decimal(value)
    except decimal.InvalidOperation as exc:
        raise ValueError("amount is not a decimal number") from exc
    places = ASSET_DECIMALS[asset]
    if not amount.is_finite() or amount <= 0:
        raise ValueError("amount must be finite and positive")
    # Bound extreme exponents before Decimal arithmetic or integer conversion.
    if amount.adjusted() < -places:
        raise ValueError(f"{asset} amounts require at most {places} decimal places")
    if amount.adjusted() > len(str(MAX_UNITS[asset])) - places:
        raise ValueError(f"{asset} amount exceeds the supported limit")
    with decimal.localcontext() as context:
        context.prec = max(100, len(amount.as_tuple().digits) + places + 1)
        units = amount * (decimal.Decimal(10) ** places)
        if units != units.to_integral_value():
            raise ValueError(f"{asset} amounts require at most {places} decimal places")
        if units > MAX_UNITS[asset]:
            raise ValueError(f"{asset} amount exceeds the supported limit")
        return str(int(units))


def identifier(value):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("offer, quote and trade IDs must be UUIDs") from exc
    if str(parsed) != value.lower() or parsed.version != 4 or parsed.variant != uuid.RFC_4122:
        raise ValueError("use the complete version-4 UUID with hyphens")
    return str(parsed)


def external_address(value, asset=None):
    if not isinstance(value, str) or not value or len(value) > 128 or value != value.strip():
        raise ValueError("provide your external ETH or Bitcoin mainnet address")
    if value.startswith("0x"):
        if asset == "BTC" or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value) or int(value[2:], 16) == 0:
            raise ValueError("use a nonzero Ethereum address (0x followed by 40 hex characters)")
    else:
        legacy = re.fullmatch(r"[13][1-9A-HJ-NP-Za-km-z]{25,34}", value)
        bech32 = (re.fullmatch(r"bc1[ac-hj-np-z02-9]{11,87}", value, flags=re.IGNORECASE)
                  and (value == value.lower() or value == value.upper()))
        if asset == "ETH" or not (legacy or bech32):
            raise ValueError("use a Bitcoin mainnet address beginning 1, 3 or bc1")
    return value


def site_origin(value):
    if not isinstance(value, str) or any(ord(char) <= 32 for char in value):
        raise ValueError("site must be an HTTPS origin")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("site must be an HTTPS origin") from exc
    if (parsed.scheme.lower() != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("site must be an HTTPS origin without credentials, a path, query or fragment")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != 443:
        authority += f":{port}"
    return "https://" + authority


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class SecureSessionPolicy(http.cookiejar.DefaultCookiePolicy):
    def __init__(self, host):
        super().__init__()
        self.host = host

    def set_ok(self, cookie, request):
        return (cookie.name == "aurion_session" and cookie.secure
                and not cookie.domain_specified and cookie.domain == self.host
                and cookie.path == "/" and super().set_ok(cookie, request))

    def return_ok(self, cookie, request):
        return (cookie.secure and urllib.parse.urlsplit(request.full_url).hostname == self.host
                and super().return_ok(cookie, request))


class MarketClient:
    def __init__(self, site=DEFAULT_SITE, timeout=20):
        self.site = site_origin(site)
        self.timeout = timeout
        host = urllib.parse.urlsplit(self.site).hostname
        self.cookies = http.cookiejar.CookieJar(policy=SecureSessionPolicy(host))
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies), NoRedirects())
        self.authenticated = False

    @staticmethod
    def _decode(response):
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise MarketError("the server response is too large")
        try:
            def invalid_constant(value):
                raise ValueError("nonfinite JSON number")
            result = json.loads(raw.decode("utf-8"), parse_float=decimal.Decimal,
                                parse_constant=invalid_constant)
        except (ValueError, UnicodeError) as exc:
            raise MarketError("the server did not return valid JSON") from exc
        if not isinstance(result, dict):
            raise MarketError("the server returned an unexpected JSON shape")
        return result

    def request(self, path, body=None):
        if not isinstance(path, str) or not path.startswith("/api/") or path.startswith("//"):
            raise ValueError("request path must remain within this site's /api/")
        data = None if body is None else json.dumps(body, separators=(",", ":"), allow_nan=False).encode()
        if data is not None and len(data) > MAX_REQUEST_BYTES:
            raise ValueError("request body is too large")
        headers = {"Accept": "application/json", "User-Agent": "Aurion-Market/0.2.0"}
        if data is not None:
            headers.update({"Content-Type": "application/json", "Origin": self.site,
                            "Sec-Fetch-Site": "same-origin"})
        request = urllib.request.Request(self.site + path, data=data, headers=headers,
                                         method="GET" if data is None else "POST")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return self._decode(response)
        except urllib.error.HTTPError as exc:
            try:
                result = self._decode(exc)
                code = result.get("error")
                # Never print an arbitrary body: a server might echo credentials.
                detail = code if isinstance(code, str) and re.fullmatch(r"[a-zA-Z0-9_\-]{1,100}", code) else "request_failed"
                if path == "/api/login":
                    detail = "sign_in_failed"
            except MarketError:
                detail = "request_failed"
            raise MarketError(f"market HTTP {exc.code}: {detail}") from None
        except (urllib.error.URLError, OSError):
            raise MarketError("could not reach the market over HTTPS") from None

    def network(self):
        return self.request("/api/network")

    def verify_network(self):
        info = self.network()
        if info.get("network") != MAINNET_NETWORK or info.get("genesis") != MAINNET_GENESIS:
            raise MarketError("network or genesis mismatch; no market action was sent")
        return info

    def login(self, email, password=None):
        if not isinstance(email, str) or len(email) > 254 or "@" not in email or any(c.isspace() for c in email):
            raise ValueError("provide the email used for your Aurion website account")
        self.authenticated = False
        self.cookies.clear()
        self.verify_network()
        if password is None:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", getpass.GetPassWarning)
                    password = getpass.getpass("Aurion website password: ")
            except getpass.GetPassWarning:
                raise MarketError("a terminal that can hide password entry is required") from None
        if not isinstance(password, str) or len(password) > 128:
            raise ValueError("password must be a string of at most 128 characters")
        try:
            result = self.request("/api/login", {"email": email.strip().lower(), "password": password})
        finally:
            password = None
        if not isinstance(result.get("account"), dict):
            raise MarketError("login did not return an account")
        if not any(cookie.name == "aurion_session" and cookie.secure for cookie in self.cookies):
            raise MarketError("login did not establish a secure session cookie")
        self.authenticated = True

    def _authenticated_request(self, path, body=None):
        if not self.authenticated:
            raise MarketError("sign in using --email before using this command")
        self.verify_network()
        return self.request(path, body)

    def offers(self, give_asset=None, receive_asset=None):
        query = {}
        if give_asset is not None:
            query["give_asset"] = asset_name(give_asset)
        if receive_asset is not None:
            query["receive_asset"] = asset_name(receive_asset)
        return self.request("/api/market/offers" + ("?" + urllib.parse.urlencode(query) if query else ""))

    def mine(self):
        return self._authenticated_request("/api/market/me")

    def create_offer(self, give_asset, receive_asset, give_amount, receive_amount,
                     address, expires_at):
        give, receive = asset_pair(give_asset, receive_asset)
        if type(expires_at) is not int or not 0 < expires_at < (1 << 53):
            raise ValueError("expiry must be an integer Unix timestamp in milliseconds")
        external = receive if give == "AUR" else give
        body = {"give_asset": give, "receive_asset": receive,
                "give_amount": amount_to_units(give_amount, give),
                "receive_amount": amount_to_units(receive_amount, receive),
                "external_address": external_address(address, external), "expires_at": expires_at}
        return self._authenticated_request("/api/market/offers", body)

    def cancel_offer(self, offer_id):
        return self._authenticated_request("/api/market/offers/" + identifier(offer_id) + "/cancel", {})

    def quote(self, sell_asset, buy_asset, sell_amount, min_buy_amount=None):
        sell, buy = asset_pair(sell_asset, buy_asset)
        body = {"sell_asset": sell, "buy_asset": buy,
                "sell_amount": amount_to_units(sell_amount, sell),
                "min_buy_amount": "1" if min_buy_amount is None else amount_to_units(min_buy_amount, buy)}
        return self._authenticated_request("/api/market/quote", body)

    def accept(self, quote_id, address):
        return self._authenticated_request("/api/market/quotes/" + identifier(quote_id) + "/accept",
                                           {"external_address": external_address(address)})

    def cancel_quote(self, quote_id):
        return self._authenticated_request("/api/market/quotes/" + identifier(quote_id) + "/cancel", {})

    def trade(self, trade_id):
        return self._authenticated_request("/api/market/trades/" + identifier(trade_id))

    def cancel_trade(self, trade_id):
        return self._authenticated_request("/api/market/trades/" + identifier(trade_id) + "/cancel", {})


def _printable(value):
    """Suppress accidental credentials in server objects before printing JSON."""
    sensitive = {"password", "seed", "private_key", "private_keys", "secret_key",
                 "token", "session", "cookie", "encrypted_wallet"}
    if isinstance(value, dict):
        return {key: _printable(item) for key, item in value.items() if key.lower() not in sensitive}
    if isinstance(value, list):
        return [_printable(item) for item in value]
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=CLI_EXAMPLES,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--site", default=DEFAULT_SITE, help="HTTPS website origin")
    parser.add_argument("--email", help="website account email; password is prompted, never a CLI argument")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("network", help="show the connected network")
    offers = sub.add_parser("offers", help="list actual public offers")
    offers.add_argument("--give", choices=list(ASSET_DECIMALS))
    offers.add_argument("--receive", choices=list(ASSET_DECIMALS))
    sub.add_parser("mine", help="show my offers, held quotes and trades; requires --email")
    offer = sub.add_parser("offer", help="publish or cancel my offer; requires --email")
    actions = offer.add_subparsers(dest="action", required=True)
    create = actions.add_parser("create", description="Choose both amounts to set your own rate; "
                                "no fixed market price is imposed. A counterparty must accept it.")
    create.add_argument("--give", required=True, choices=list(ASSET_DECIMALS))
    create.add_argument("--receive", required=True, choices=list(ASSET_DECIMALS))
    create.add_argument("--give-amount", required=True, help="positive coin amount you offer")
    create.add_argument("--receive-amount", required=True, help="positive coin amount you request; "
                        "together with --give-amount this sets your price")
    create.add_argument("--external-address", required=True)
    create.add_argument("--expires-hours", type=int, default=24)
    actions.add_parser("cancel").add_argument("id")
    quote = sub.add_parser("quote", help="reserve a matching real offer; requires --email",
                           description="Match a real counterparty at an acceptable rate. "
                           "A quote can fill only part of your budget; review its exact amounts.")
    quote.add_argument("--sell", required=True, choices=list(ASSET_DECIMALS))
    quote.add_argument("--buy", required=True, choices=list(ASSET_DECIMALS))
    quote.add_argument("--amount", required=True, help="maximum coin amount you are willing to pay")
    quote.add_argument("--min-buy", help="minimum coin amount you accept receiving; "
                       "default one smallest unit")
    sub.add_parser("quote-cancel", help="release a held quote").add_argument("id")
    accept = sub.add_parser("accept", help="accept a quote; creates an unfunded trade, not a payment")
    accept.add_argument("id")
    accept.add_argument("--external-address", required=True)
    trade = sub.add_parser("trade", help="inspect or cancel an unfunded trade")
    trade_actions = trade.add_subparsers(dest="action", required=True)
    trade_actions.add_parser("status").add_argument("id")
    trade_actions.add_parser("cancel").add_argument("id")
    args = parser.parse_args(argv)
    try:
        client = MarketClient(args.site)
        if args.email:
            client.login(args.email)
        elif args.command not in ("offers", "network"):
            parser.error("this command requires --email before the command")
        if args.command == "network":
            result = client.network()
        elif args.command == "offers":
            result = client.offers(args.give, args.receive)
        elif args.command == "mine":
            result = client.mine()
        elif args.command == "offer":
            if args.action == "cancel":
                result = client.cancel_offer(args.id)
            else:
                if not 1 <= args.expires_hours <= 24 * 30:
                    raise ValueError("offer expiry must be between 1 and 720 hours")
                expiry = int(time.time() * 1000) + args.expires_hours * 3_600_000
                result = client.create_offer(args.give, args.receive, args.give_amount,
                                              args.receive_amount, args.external_address, expiry)
        elif args.command == "quote":
            result = client.quote(args.sell, args.buy, args.amount, args.min_buy)
        elif args.command == "quote-cancel":
            result = client.cancel_quote(args.id)
        elif args.command == "accept":
            result = client.accept(args.id, args.external_address)
        else:
            result = client.trade(args.id) if args.action == "status" else client.cancel_trade(args.id)
        print(json.dumps(_printable(result), indent=2, default=str))
        return 0
    except (MarketError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("market command cancelled", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
