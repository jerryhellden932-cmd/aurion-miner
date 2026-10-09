# Aurion exchange integration — unaudited experimental network

Aurion is an experimental native blockchain asset, symbol **AUR**, with eight decimal places. It is not an ERC-20 token, has no EVM contract address, and is not listed on an exchange by this kit. The founder has authorized an unaudited experimental mainnet launch. The published seed endpoint is `node.aurioncoin.io`; confirm its live availability, transport and the release's exact genesis fingerprint before connecting. The `mainnet` label does not establish production security. This release has no independently audited consensus or supported real-money deposit service. A local REST adapter and an exact-unit Python client let exchange engineers experiment with their own independently verifying nodes.

The maximum supply design is 21,000,000 AUR (`2100000000000000` base units). The launch founder allocation is 0.1%, 21,000 AUR (`2100000000000` base units), in the published genesis. Private test networks can configure their own founder. The allocation and founder address change the genesis hash. No founder keys or custodial wallet are created by the exchange kit.

## Run a private adapter

Requires Python 3.10 or later. The adapter and client use only the standard library. Start an experimental Aurion node using its documented instructions, then inspect its `/info` response independently. Pin both the exact network name and the genesis hash. Never copy a genesis pin from an untrusted API without verifying the network's published release and independently calculating its genesis.

```sh
python3 coin/aurion.py --network testnet node --bind 127.0.0.1 --port 17333
```

In a second terminal, replace `VERIFIED_GENESIS_HASH` with your independently verified 64-character lowercase hash:

```sh
python3 coin/exchange_api.py --upstream http://127.0.0.1:17333 --network aurion-testnet --genesis VERIFIED_GENESIS_HASH
python3 coin/exchange_client.py --network aurion-testnet --genesis VERIFIED_GENESIS_HASH network
```

The adapter binds to `127.0.0.1:17334` by default, forwarding to `127.0.0.1:17333`. It has no login, key store, wallet creation or signing endpoint. Keep it on a private host/network; provide authentication, TLS, access control, request limits and monitoring at your own gateway if remote services need access. Signed transactions only are broadcast. Reads can run without pins for exploration; broadcasts require both pins. Using testnet with a configured founder requires that node's specific genesis pin. For the experimental mainnet, follow the launch manifest and node instructions, run your own verifying node, use `aurion-mainnet` as the exact network pin and the independently verified published genesis hash, and point this adapter at that local node. Mainnet commands require the node software's explicit `--allow-unaudited-mainnet` flag.

## API

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/v1/network` | Experimental flag, exact network/genesis, current canonical tip, base unit constants. |
| GET | `/v1/addresses/{address}` | Balance, locked/spendable base units, last used signature index. |
| GET | `/v1/checkpoints?from=1&limit=500` | Canonical checkpoints with their hashes and pagination cursor. |
| GET | `/v1/transactions/{txid}?from=1&limit=500` | Local transaction, bounded DAG reference scan, recent canonical execution receipt when available. |
| POST | `/v1/transactions` | Broadcast an already signed transaction. Returns HTTP 202 for node acceptance/duplicate, never payment settlement. |

Amounts and fees are **decimal integer strings of base units** in API requests and responses, e.g. `"100000000"` is 1 AUR. Do not use floating-point arithmetic. Heights, timestamps and signature indices are JSON integers. Native node transaction bodies use integer amounts; the adapter converts API amount/fee strings back to those exact integers before hashing and broadcast, preserving the signature. `exchange_client.py` also accepts signed native-node envelopes and performs this normalization. Never sign the API string representation directly.

`txid = SHA3-256("TX" || canonical_json(native_transaction_body))`; checkpoint hashes use prefix `"CP"` instead. Canonical JSON sorts object keys, uses compact separators and the node's integer monetary representation. Signatures are not part of these identifiers. The network fingerprint is `SHA3-256(UTF8(network + ":" + genesis_hash))`. A fingerprint does not authenticate a peer; pin its verified inputs.

HTTP 400 indicates malformed input, 409 a mismatched pin or changing canonical tip (retry a read), 413 excessive request size, 415 wrong request content type, 422 upstream transaction rejection, and 502 unavailable/inconsistent upstream data. If broadcast returns 409 after submission, its side effect may already have occurred; query the known transaction ID before deciding whether to rebroadcast the same signed envelope. Never create a fresh signature as a retry.

## Canonical inclusion is not deposit credit

The underlying node checkpoints contain DAG tips, not complete transfer execution lists. A referenced transaction can be rejected by account rules, expired, or belong to a branch that is later abandoned. A node knowing a transaction is not evidence it is pending or applied. The adapter reports:

- `applied` or `rejected`: a recent canonical node execution receipt, checked against the current checkpoint hash and tip; `application_verified=true`.
- `canonical_reference`: found in a canonical checkpoint's reachable DAG, but its successful application is unverified; `application_verified=false`.
- `unknown`: no verified receipt or reference found within the stated scan. This never means absent from all chain history, and never establishes mempool, rejected or orphan status.

Every lookup includes scan bounds, missing ancestors, DAG work-limit status, and whether the reference scan covered the entire canonical chain. Defaults inspect checkpoints 1–500, with at most 20,000 distinct DAG transactions; paginate explicitly. The upstream can cap chain pages at 500. Receipts are currently pruned with the node's processed-transaction history, approximately two hours of checkpoint time. Historical reference scans cannot reconstruct execution outcomes. For a durable deposit index, maintain your own independently verified canonical execution history and record applied transfers as each checkpoint is validated. If an applied receipt is pruned, `unknown` is expected; do not infer that a prior transfer was undone. The adapter deliberately does not invent execution or orphan status.

`confirmations` counts checkpoints after the identified inclusion plus one. It is **not economic finality, a proof of consensus security, or a safe deposit threshold**. All responses state `finality="unproven"`; `deposit_eligible=false` and `real_money_deposits_enabled=false` remain unconditional in this release. Even `application_verified=true` trusts this local node's experimental execution and does not establish that its consensus is secure.

For exchange research, operate independent nodes, compare pinned identities and canonical tips, and halt settlement when they disagree. Persist checkpoint hashes by height. Reconcile from the last common ancestor after any reorganization, reverse credits from abandoned checkpoints, and replay the replacement branch. Changes can occur while a response is assembled; the adapter checks the tip before and after and returns 409 when it changes. A local 100-checkpoint reorg bound is a software rule, not a finality guarantee or defense against a compromised/isolated network. Keep test balances isolated from real deposits and trading.

## Wallet signing constraints

Each address has **1,024 one-time signatures**, shared by transfers and any mining/checkpoint signing performed with that key. Never reuse a signature index, restore an old wallet backup and resume signing, or let independent services sign with copies of one wallet. Coordinate a single durable signer; reserve indices before signing, retain monotonic counters across retries/restarts, and rotate well before exhaustion. Deposit wallets that only receive do not consume indices until they sign a sweep. Mining production keys should be separate from deposit/withdrawal keys. The kit accepts no private key, seed, password or unsigned signing request.

Website transfers reserve an index durably in the account before browser-only signing. A cancelled or failed signing attempt still consumes that reservation; it cannot be rolled back. Export a fresh wallet backup after signing and reload the current account before exporting. A website counter cannot prevent an independent desktop wallet copy from signing with an old index, particularly while a transaction is unconfirmed. Choose one signing environment per wallet and do not sign concurrently from website and desktop copies.

Use independent security review before considering custody or a mainnet. Hash-based signatures are an experimental post-quantum design here; this does not make the network "quantum proof" or guarantee safety.

## Python integration

```python
from coin.exchange_client import ExchangeClient

client = ExchangeClient(network="aurion-testnet", genesis="your_verified_genesis_hash")
network = client.network_info()
page = client.checkpoints(start=1, limit=100)
for checkpoint in page["checkpoints"]:
    print(checkpoint["height"], checkpoint["hash"])
# Process verified local execution receipts; do not credit DAG references.
# Parse exact money using int(result["balance_units"]), never float().
```

`docs/openapi.json` describes these endpoints. Package `coin/exchange_api.py`, `coin/exchange_client.py`, this guide and the schema together for integrators. This kit is a prototype interface, not an exchange partnership, asset listing or production custody service.
