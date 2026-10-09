# Aurion 0.2 security status

This public network is an **unaudited experimental mainnet**. It is not proven
quantum resistant, production ready, or suitable for protecting valuable assets.
The founder explicitly requested a public launch after these limitations were
explained. Publishing this network does not resolve them.

## Confirmed launch risks

- Storage proofs are recomputable from public inputs. A declared plot size is
  not evidence that the corresponding space was allocated. The advertised
  storage security requires a different consensus construction.
- Producers influence future challenges through proof selection. Chain weight,
  challenge grinding, reorganization behavior and economic incentives need
  adversarial review. A checkpoint count does not guarantee finality.
- Signatures are a custom WOTS/Merkle construction, not a standardized XMSS
  implementation. One-time signing keys must not be reused. A wallet and a plot
  each have a finite signing capacity; rotation and recovery remain incomplete.
- HTTP gossip and peer discovery lack mature rate limiting, scoring and
  protection from hostile public peers. The initial network has one hosted seed
  and cannot claim resilient decentralization.
- Ledger state grows in memory. The hosted seed replays a durable journal after
  restart. Long-term scaling and operational recovery are not established.
- Bitcoin HTLC generation does not provide complete Bitcoin settlement,
  signing, watching, deadline negotiation or an audited trading application.
  Timeout examples must be recalculated for the selected network. Never assume
  script generation alone establishes safe cross-chain trading.

## Changes verified in this release

Same-file wallet writers now use a persistent cross-process lock, reload durable
signing state and reserve indices before signing. Private writes use restricted
permissions. This does not protect copies, restored backups, multiple devices,
or a website export that predates desktop signing. Keep one current signing
copy. Website sends reserve an index in durable account storage before the
browser signs; failed sends still consume that index. Reservations protect
concurrent website sessions, but cannot coordinate unconfirmed signing from
old exports or desktop copies. Choose one current signing location.

Applied HTLC receipts are retained for long-lived swap verification. Ordinary
transfer receipts remain bounded. The peer offer book reserves metadata, never
funds. Ethereum settlement checks a fixed mainnet RPC endpoint and canonical
anchors; Bitcoin HTLC settlement is manual. Quotes and matched trades are not
payments or guaranteed conversions.

Canonical receipts distinguish an applied transaction from a referenced but
rejected transaction. Receipts are bounded; an unknown receipt must never credit
an exchange deposit. Exchanges need independent replay and reorganization
handling before considering a production integration.

Browser wallets use locally vendored SHA3/SHAKE and scrypt libraries, matching
the Python wallet format. Account passwords are hashed separately; encrypted
wallet seeds are stored privately. Account and browser compatibility tests do
not establish cryptographic certification.

## Required before claiming real-funds readiness

Redesign and analyze consensus, choose a standardized post-quantum signature
implementation, solve signing-state recovery and key rotation, conduct
independent cryptography/consensus audits, run hostile-peer and reorganization
testing, and establish multiple independent long-running nodes with monitoring
and recovery procedures. No exchange listing, buyer, liquidity, or market price
is promised by this release.
