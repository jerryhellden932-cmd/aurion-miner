# Native ETH settlement

The website and desktop package can prepare transactions for a native-ETH hash-time-locked contract. Ethereum signing stays in a connected Ethereum wallet. The website does not store Ethereum keys. The CLI builds unsigned transaction JSON and reads a configured JSON-RPC endpoint; it never signs or broadcasts. This does not create an ERC-20 AUR token, bridge AUR, supply an exchange price, or supply a counterparty.

`AurionHTLC.artifact.json` contains actual compiled creation bytecode, runtime bytecode, ABI and compiler method selectors. It was compiled with official Solidity `0.8.26+commit.8a97fa7a`, optimizer enabled with 200 runs, EVM target `paris`. The compiler JavaScript SHA-256 was checked against the official Solidity manifest before compilation. The contract has not been deployed or independently audited. `deployedAddress` remains `null` until a real deployment is confirmed; it is never an invented address.

## Deploy and verify

1. Use an Ethereum mainnet wallet with ETH available for deployment gas. Connect it to the website and select Ethereum mainnet. AUR balances cannot pay Ethereum gas.
2. Call the website's deployment action. The browser fetches the compiled artifact and submits an unsigned deployment to the connected EIP-1193 wallet. Review and approve it there.
3. Save the transaction hash. Check its deployment receipt until mined. The helper compares `eth_getCode` at the returned contract address against the exact supplied runtime bytecode before accepting the address.
4. Check canonical inclusion and Ethereum finality independently. A transaction hash or mined receipt is not a finality guarantee. Publish the verified contract address, chain ID 1, deployment hash and source/artifact together so counterparties can check them.

The contract has no owner and no upgrade, mint, price, custody or administration function. Each lock has its own fixed sender, fixed recipient, amount, SHA-256 hashlock and deadline. Only that recipient can claim, and only that sender can refund. Both addresses must accept native ETH; a contract address whose receive function rejects ETH can block its own payout. There is no rescue administrator.

## Matched trades on the website

The `/trade` page matches participant offers and guides AUR/ETH settlement. A match reserves an offer; it does not transfer funds. The AUR sender derives a separate deterministic secret for the trade from their encrypted AUR wallet on their device. Only that participant can publish the hashlock terms. Keep the wallet backup and password: they are needed to recover the trade secret. The ETH sender must never choose or learn the secret before the ETH claim is submitted.

Quoted AUR amounts are net. The AUR lock contains the agreed amount plus 1,000 base units for the recipient's claim fee; the sender additionally pays a 1,000-unit lock fee. The guide uses a timeout 2,880 checkpoints beyond the observed AUR tip and an ETH deadline 24 hours after terms are prepared. It requires the AUR lock to gain 100 checkpoints of depth before ETH funding, checks Ethereum lock finality before the secret reveal, and requires at least one hour remaining on the ETH deadline plus a substantial AUR checkpoint margin. These are workflow guards, not guarantees of finality or transaction inclusion.

Every funding, claim and refund needs a user click and either a local AUR wallet signature or approval in the Ethereum extension. Public transaction IDs are saved before their reports are sent so an uncertain network response cannot silently trigger another funding attempt. A reported ID alone never completes a trade. The server checks retained canonical AUR execution receipts, exact amounts and participants, SHA-256 commitments, checkpoint anchors, Ethereum mainnet identity, exact compiled runtime bytecode, receipt events and contract state. It uses the connected AUR seed and the fixed public Ethereum RPC endpoint `https://ethereum-rpc.publicnode.com`; independent chain validation remains necessary for real-funds decisions.

`completed_verified` requires both matching claims, a finalized ETH claim, and an AUR claim at least 100 checkpoints behind the tip (101 inclusive confirmations). AUR finality remains unproven. Refunds remain `recovery_pending` until both refund legs pass their maturity checks. Selected visible trades are rechecked at most once per minute, including completed trades, and a reorganization can downgrade the recorded result. A verified rejected/reverted transaction can expose an explicit retry action after its failure anchor matures; pending or uncertain submissions remain blocked. Bitcoin matches use the manual P2WSH workflow in `TRADE.md` and never receive an invented automatic-settlement result.

## Website API

Load `eth-settlement.js` after connecting an EIP-1193 provider. The global `AurionEthereum` API exposes:

```javascript
const txHash = await AurionEthereum.deployContract(provider);
const deployed = await AurionEthereum.deploymentReceipt(provider, txHash);
// When deployed.status is "mined", deployed.contractAddress was bytecode checked.

const lockHash = await AurionEthereum.lockETH(
  provider, contractAddress, recipientAddress, hashlockHex, deadlineUnix, "0.01"
);
const locked = await AurionEthereum.inspectReceipt(provider, contractAddress, lockHash);
// For a mined lock: locked.locks[0].id is the contract's emitted swap ID.
const state = await AurionEthereum.swapStatus(provider, contractAddress, swapId);
const claimHash = await AurionEthereum.claim(provider, contractAddress, swapId, secretHex);
const refundHash = await AurionEthereum.refund(provider, contractAddress, swapId);
```

Use exact decimal strings for ETH amounts with at most 18 decimal places; values are converted with BigInt. A secret, hashlock or swap ID is exactly 32 bytes, encoded as 64 hexadecimal digits with an optional `0x` prefix. The browser checks mainnet and exact contract runtime before each settlement, checks parties and deadlines before claim/refund, and computes SHA-256 locally before asking the wallet to reveal a secret. The wallet prompts for every transaction and manages gas. The artifact is served from `/downloads/AurionHTLC.artifact.json`.

## Desktop CLI

Examples use placeholder addresses and values. Replace them with the participants' verified addresses and negotiated terms. Never pass an Ethereum private key to these commands.

```bash
python3 coin/ethereum_swap.py deploy --sender 0x1111111111111111111111111111111111111111

python3 coin/ethereum_swap.py lock \
  --sender 0x1111111111111111111111111111111111111111 \
  --contract 0x2222222222222222222222222222222222222222 \
  --recipient 0x3333333333333333333333333333333333333333 \
  --hash YOUR_64_HEX_SHA256_HASH --expires-at YOUR_FUTURE_UNIX_TIMESTAMP --eth 0.01

python3 coin/ethereum_swap.py status --rpc https://YOUR_ETHEREUM_RPC \
  --contract YOUR_VERIFIED_CONTRACT --id YOUR_64_HEX_SWAP_ID

python3 coin/ethereum_swap.py claim --sender YOUR_ETH_RECIPIENT \
  --contract YOUR_VERIFIED_CONTRACT --id YOUR_SWAP_ID --preimage YOUR_32_BYTE_SECRET_HEX

python3 coin/ethereum_swap.py refund --sender YOUR_ETH_SENDER \
  --contract YOUR_VERIFIED_CONTRACT --id YOUR_SWAP_ID

python3 coin/ethereum_swap.py receipt --rpc https://YOUR_ETHEREUM_RPC --tx YOUR_DEPLOYMENT_TX_HASH
python3 coin/ethereum_swap.py receipt --rpc https://YOUR_ETHEREUM_RPC \
  --contract YOUR_VERIFIED_CONTRACT --tx YOUR_SETTLEMENT_TX_HASH
```

Generated `transaction` JSON is unsigned: review it and import it into an Ethereum wallet that supports transaction requests. A CLI transaction builder can run offline and therefore reports `contractVerified: false`. Use the `status`/`receipt` commands or independently verify runtime before approving it. Fee fields and nonce are deliberately left to the wallet. An alternative artifact location can be supplied with the global `--artifact PATH` argument, before the command. In the downloadable bundle the default artifact is `docs/AurionHTLC.artifact.json`.

## AUR/ETH hashlock workflow and deadlines

Alice sells AUR to Bob for ETH. Alice generates a random 32-byte secret `S`; both chains commit to `SHA256(S)`. Alice first locks AUR for Bob with the longer refund deadline. After Bob independently verifies that the AUR lock actually executed on canonical history with the correct amount, recipient and hashlock, Bob locks ETH for Alice with the shorter Unix deadline. Alice verifies the contract runtime, ETH lock terms, sender and amount, and waits for suitable Ethereum finality. Alice claims ETH, revealing `S`. Bob reads the public preimage and claims AUR before the longer AUR deadline. If the ETH leg is never opened, Alice refunds AUR after its timeout. If Alice never claims ETH, Bob refunds ETH at or after its Unix deadline, and Alice can later refund her AUR.

Reverse the party and asset roles for the other direction. Keep the leg claimed with the secret first on the shorter deadline, and leave enough time to learn its confirmed preimage and submit the second claim. Never reveal `S` before both locks are verified. Claims reveal the secret in public Ethereum calldata and events. A command-line secret argument may also appear in shell history or process listings; preserve the secret privately until the planned claim.

AUR timeouts are **checkpoint heights**: `aurion.py swap lock --timeout N` means N checkpoints beyond the current height. Mainnet targets 60 seconds per checkpoint, so 2,880 checkpoints targets about 48 hours, not 24 hours. The actual interval can vary or stall. AUR accepts claims through `height <= timeout` and refunds only at `height > timeout`. ETH accepts claims only when `block.timestamp < expiresAt` and refunds at `block.timestamp >= expiresAt`. ETH lock deadlines are future Unix timestamps no more than 30 days ahead. Heights and Unix timestamps cannot be converted into guaranteed relative finality. Observe actual chain progress and use a substantial margin rather than relying on nominal intervals.

Read `SECURITY.md`, `TRADE.md` and `EXCHANGE.md` for the chain's known consensus, inclusion and receipt limitations. An HTLC cannot make an unreliable chain safe, guarantee cross-chain finality, or guarantee that real ETH exchanged against AUR can be recovered after a stall or reorganization. Neither BTC nor Ethereum uses Aurion's wallet signatures, and those chains do not become quantum resistant through this integration. There is no automatic exchange listing, liquidity provider, execution quote, or assured market value.
