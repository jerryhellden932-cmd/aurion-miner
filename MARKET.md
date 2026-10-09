# Hosted Aurion offer book

`market_client.py` connects to the offer book on https://aurioncoin.io. People publish their own AUR/ETH or AUR/BTC amounts. The service matches an existing counterparty offer and can reserve a partial fill. It does not invent a price, supply liquidity, debit a wallet, broadcast a payment, or guarantee that a trade will settle. An empty book returns `no_matching_offer`.

**You choose the rate on both the website and in the software.** Set the AUR amount you offer and the ETH or BTC amount you request. Your requested external amount divided by your offered AUR amount is your ETH-per-AUR or BTC-per-AUR price. No platform price is imposed: any positive ratio representable by the supported coin precision and amount limits is allowed. You can also offer ETH or BTC and request AUR. A rate you publish does not obligate another person to accept it.

This is an unaudited experimental mainnet with known consensus and signature weaknesses. Read [SECURITY.md](SECURITY.md), [TRADE.md](TRADE.md) and [ETHEREUM.md](ETHEREUM.md) before risking funds. Matching an offer does not remove those risks or establish AUR's monetary value.

Use Python 3.9 or newer. Windows can use `py` instead of `python3`; macOS and Linux usually use `python3`. Run commands from the extracted download directory.

```bash
python3 market_client.py network
python3 market_client.py offers
python3 market_client.py offers --give AUR --receive ETH
python3 market_client.py offers --give BTC --receive AUR
```

The filters describe what the **maker** gives and receives. A quote describes what **you** sell and buy. To buy AUR with ETH, inspect makers giving AUR and receiving ETH, then request a quote selling ETH and buying AUR.

Create an account and wallet on the website first. Authenticated commands require its email before the command and prompt for the website password privately. Passwords are never command-line options. The client accepts only HTTPS, refuses redirects, sends the required matching `Origin` header on POST, and keeps its secure session cookie in memory for that process. It saves no passwords, cookies or private keys. Each authenticated action checks the published mainnet name and genesis hash through `/api/network` before sending the market request.

Publish your own offer, replacing the placeholders with amounts and an external wallet address you control:

```bash
python3 market_client.py --email <EMAIL> offer create --give AUR --receive ETH --give-amount <AUR_AMOUNT> --receive-amount <ETH_AMOUNT> --external-address <YOUR_ETH_ADDRESS> --expires-hours 24
python3 market_client.py --email <EMAIL> offer create --give AUR --receive BTC --give-amount <AUR_AMOUNT> --receive-amount <BTC_AMOUNT> --external-address <YOUR_BTC_ADDRESS> --expires-hours 24
python3 market_client.py --email <EMAIL> mine
python3 market_client.py --email <EMAIL> offer cancel <OFFER_UUID>
```

`mine` shows your offers, held quotes and trades; it does not start a miner. Every offer needs the maker's external ETH or Bitcoin address, including offers that give the external asset. The book's address validation checks shape, not checksum or ownership. Independently check addresses in your wallet. Offers expire within 30 days. Publishing an AUR-selling offer requires enough spendable AUR for the promised amount and the two minimum AUR fees; balances are not escrowed by publishing it.

Request a real matching quote, review it, then accept or release it:

```bash
python3 market_client.py --email <EMAIL> quote --sell ETH --buy AUR --amount <MAX_ETH_BUDGET> --min-buy <MIN_AUR_RECEIVED>
python3 market_client.py --email <EMAIL> accept <QUOTE_UUID> --external-address <YOUR_ETH_ADDRESS>
python3 market_client.py --email <EMAIL> quote-cancel <QUOTE_UUID>
python3 market_client.py --email <EMAIL> trade status <TRADE_UUID>
python3 market_client.py --email <EMAIL> trade cancel <TRADE_UUID>
```

For Bitcoin, use the same matching workflow with BTC amounts and your Bitcoin mainnet address:

```bash
python3 market_client.py offers --give AUR --receive BTC
python3 market_client.py --email <EMAIL> quote --sell BTC --buy AUR --amount <MAX_BTC_BUDGET> --min-buy <MIN_AUR_RECEIVED>
python3 market_client.py --email <EMAIL> accept <BTC_QUOTE_UUID> --external-address <YOUR_BTC_ADDRESS>
python3 market_client.py --email <EMAIL> trade status <BTC_TRADE_UUID>
```

To sell AUR into a counterparty's existing ETH or BTC offer, reverse `--sell` and `--buy` and enter your AUR budget and minimum external amount. If available offers do not meet your minimum receipt, no matching quote is created. You can publish your own offer at your preferred rate and wait for a counterparty instead.

Quotes hold the selected offer for up to five minutes. Review `pay_amount` and `buy_amount`: your sell budget can produce a partial fill, so the actual payment can be lower than the budget. If you omit `--min-buy`, the minimum is one smallest unit of the received asset. Acceptance creates an `awaiting_settlement` trade with an unfunded reservation deadline; it is not payment confirmation. A new process signs in again, so complete acceptance before the quote expires.

CLI amounts are decimal **coin amounts**, with at most eight decimal places for AUR/BTC and eighteen for ETH. They are converted with `decimal.Decimal` to exact integer strings. API results show **base-unit strings**, never floating-point prices. One AUR/BTC is 100,000,000 base units; one ETH is 1,000,000,000,000,000,000 wei. AUR trade `aur_amount` is the agreed net amount: the sender needs an additional 2,000 base units for the minimum lock and claim fees, and the lock amount includes the 1,000-unit claim fee.

After accepting, open https://aurioncoin.io/trade, sign in to the same account, and select the trade under **Your offers, quotes and trades**. For ETH, use its guided wallet settlement workflow, check the verified deployment and both parties' details, and review every transaction in your external wallet. Each on-chain approval remains separate. For BTC, use the manual Bitcoin wallet/script tooling described in `TRADE.md`; book acceptance does not construct or broadcast a Bitcoin transaction. Completion must come from independently checked canonical AUR receipts and external-chain evidence, not a counterparty's claim or a button press.

Cancelling a quote or an unfunded trade releases a book reservation. It cannot reverse a funded HTLC or refund funds from a chain. Funded claims and refunds use the relevant wallet and contract timeout. Network stalls, reorganizations, unavailable counterparties, fees and the known Aurion flaws can prevent safe completion.

The default origin is `https://aurioncoin.io`. `--site` accepts another HTTPS origin only when you deliberately choose a compatible deployment with the identical published Aurion mainnet genesis. Never enter your website password at an origin you do not trust.
