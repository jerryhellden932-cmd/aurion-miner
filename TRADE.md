# AUR/BTC and AUR/ETH trade tools

The Aurion software includes experimental AUR hash-time-locked transactions (HTLCs), a Bitcoin matching-script generator, and a client for the live website's user-priced offer book. The website automatically matches AUR/ETH and AUR/BTC offers and guides wallet-approved AUR/ETH settlement. This package also includes **unaudited, undeployed** native-ETH HTLC source, a compiled artifact and an ABI. Matching does not supply liquidity, establish an exchange listing or price, debit wallets, or prove that a trade completed. ETH settlement needs an actual verified deployment and funded wallet; Bitcoin settlement remains manual.

Aurion is a native asset on its own experimental chain. It has no ERC-20 contract address, and the ETH HTLC does not mint or bridge AUR. No BTC, ETH or AUR custody is provided by the exchange adapter. BTC and ETH accounts are not made quantum resistant by exchanging for AUR. Aurion itself remains an unaudited prototype with known consensus risks.

## What works in this release

| Component | Delivered behavior | Remaining requirements |
| --- | --- | --- |
| AUR software | Generate a 32-byte secret and SHA-256 commitment; sign/broadcast AUR HTLC lock, claim and refund; query HTLC state. | Own funded experimental wallet, correct signature indices, connected verifying node and canonical execution checks. |
| BTC software | Produce a matching native-SegWit P2WSH witness script/address and witness instructions. | Separate Bitcoin wallet/Core tooling to construct, fund, sign and broadcast claim/refund transactions; correct fees/locktime and network. |
| ETH developer kit | Native-ETH Solidity HTLC source, compiled artifact and ABI; deployment, lock, claim and refund builders. | Full EVM lifecycle testing, independent audit, deliberate deployment to Ethereum mainnet, verified bytecode and funded gas. |
| Website | Accounts, AUR signing, external ETH/BTC wallet connections, user-priced offer matching, and guided AUR/ETH settlement with canonical evidence checks. | A real counterparty, actual funding and verified ETH deployment; manual Bitcoin transaction tooling; independent review before valuable funds. |
| Downloaded market client | Publish offers, obtain exact partial-fill quotes, accept/cancel matches and inspect trades on the same hosted book. | Website account, suitable offers and separate wallet settlement. See `MARKET.md` for both ETH and BTC examples. |

The founder authorized an experimental Aurion mainnet. That authorization does not validate these cross-chain contracts or make real funds safe. Develop and verify BTC/ETH legs on local or test networks first. The ETH contract has been compiled with the checksum-verified Solidity 0.8.26 compiler. The compiled artifact, ABI and wallet settlement controls are included. It has not been deployed, funded, audited or exercised through a full EVM settlement lifecycle. Compilation and provider checks are not a security audit. See `ETHEREUM.md` for the deployment and transaction workflow.

## Shared swap protocol

Agree on exact amounts, both chain identities, recipient/refund addresses, the SHA-256 hashlock and staggered timeouts. Alice holds AUR and generates a fresh, uniformly random **32-byte preimage**, keeping it private. She publishes only `SHA256(preimage)` and creates the longer-lived AUR lock for Bob. Bob independently verifies that lock's actual canonical execution, amount, recipient, hash and remaining lifetime before funding the shorter-lived BTC or ETH leg for Alice. Alice verifies Bob's leg and claims it by revealing the preimage. Bob observes the published preimage and claims AUR before its longer deadline. Each original sender can refund their own still-open leg after that leg's timeout.

Use a fresh secret for every swap. A previously published preimage can immediately unlock later contracts using the same hash. Never send a preimage to an unverified counterparty or put it in a website preview, support chat or analytics log. The act of claiming the short leg publishes the secret permanently in public transaction data, including pending transaction pools before confirmation.

The BTC/ETH refund must become available **earlier** than the AUR refund. AUR uses checkpoint heights, Bitcoin uses an absolute block height in this generator, and ETH uses Unix timestamps. These are different clocks: convert using conservative assumptions about actual intervals and worst-case delays, including network outages, reorganizations, fee congestion and monitoring time. Aurion regtest has no fixed wall-clock checkpoint interval. The AUR code permits a claim at its timeout height and refunds only after that height; the ETH contract permits a claim strictly before the deadline and a refund at/after it. Never map these boundaries mechanically.

An HTLC cannot compensate for an insecure chain or guarantee atomic settlement across unreliable consensus. A participant who locks real BTC/ETH against experimental AUR can lose those funds if Aurion stalls or reorganizes, or if they cannot make their AUR claim in time. Monitor both chains independently for the entire swap and keep fee funds and refund tooling ready. A reference in a checkpoint alone does not establish an applied AUR lock or claim; use canonical execution receipts and your independently verified history as described in `EXCHANGE.md`.

## AUR commands

The following examples use testnet and an explicit local node. Replace the uppercase placeholders; never paste a private key or wallet password into a web form.

```sh
python3 coin/aurion.py --network testnet swap secret
python3 coin/aurion.py --network testnet --node http://127.0.0.1:17333 swap lock --to BOB_AUR_ADDRESS --amount 100 --hash HASH --timeout 2880 --file alice-wallet.json
python3 coin/aurion.py --network testnet --node http://127.0.0.1:17333 swap status --contract AUR_LOCK_TRANSACTION_ID
python3 coin/aurion.py --network testnet --node http://127.0.0.1:17333 swap claim --contract AUR_LOCK_TRANSACTION_ID --preimage PREIMAGE --file bob-wallet.json
python3 coin/aurion.py --network testnet --node http://127.0.0.1:17333 swap refund --contract AUR_LOCK_TRANSACTION_ID --file alice-wallet.json
```

Use `claim` or `refund` as appropriate; those two commands are alternative outcomes of one lock. The lock ID is its AUR transaction ID. Node submission success is not application. Inspect canonical execution and the `/htlc/{id}` state. Wallets have only 1,024 one-time signature indices; coordinate signing and never restore an old backup and resume using its old indices.

For the published experimental mainnet, use the release's verified genesis and node endpoint, replace `--network testnet` with `--network mainnet --allow-unaudited-mainnet`, and independently check the launch manifest. These command switches do not make a swap safe.

## BTC leg

For local Bitcoin regtest, choose P2WPKH addresses on that network and a future **absolute Bitcoin block height**:

```sh
python3 coin/aurion.py --network regtest swap btc-script --hash HASH --recipient-btc ALICE_BCRT1Q_ADDRESS --refund-btc BOB_BCRT1Q_ADDRESS --locktime BTC_REFUND_HEIGHT
```

The generator prints the witness script, matching P2WSH address and witness stack formats. The Bitcoin network prefix is selected by `--network` (`bcrt` for regtest, `tb` for testnet, `bc` for mainnet). AUR and BTC testnet are independent networks even if their names are similar. Verify the entire decoded script and destination before funding. The claim witness is `<signature> <public-key> <32-byte-preimage> 01 <witness-script>`. The refund witness is `<signature> <public-key> <empty-selector> <witness-script>`, with transaction `nLockTime >= BTC_REFUND_HEIGHT` and an input `nSequence < 0xffffffff`. Select suitable sighash, sequence, fees and transaction version with reviewed Bitcoin tooling.

This release does not construct or broadcast a complete Bitcoin transaction. Use Bitcoin Core PSBT/custom-witness tooling or a reviewed library capable of spending the generated P2WSH script. Verify claim and refund transactions on regtest before funding any Bitcoin leg. There is no claim that a generic Bitcoin wallet can spend this custom script automatically.

The Bitcoin script's claim branch has no expiry restriction. Once the refund height is reached, a valid secret claim and a valid sender refund can compete to spend the same output. Reaching that height does not disable claims or guarantee that a refund will win; keep monitoring until your chosen transaction is confirmed.

## ETH leg

`contracts/AurionHTLC.sol` uses Solidity `^0.8.24`, native ETH only, a fixed sender and recipient per lock, exact 32-byte SHA-256 preimages, monotonic per-sender nonces and IDs committing to chain/contract/participants/amount/hash/deadline. Deadlines must be in the future and no more than 30 days ahead. All money-moving functions use a reentrancy guard; claim/refund mark the lock closed before the external ETH transfer and revert completely if that transfer fails. There is no owner, administrator, ERC-20 support, AUR bridge or key store.

- `lock(recipient, hashlock, expiresAt)` is payable. `msg.value` is the exact ETH amount in wei. The `Locked` event publishes the swap ID; use it for later calls.
- `swaps(id)` returns sender, recipient, hashlock, Unix deadline, original wei amount and state: `0=Unknown`, `1=Open`, `2=Claimed`, `3=Refunded`.
- `claim(id, preimage)` requires the recipient's transaction, the exact preimage and a timestamp strictly before expiry. The `Claimed` event and transaction calldata publish the preimage.
- `refund(id)` requires the original sender's transaction and a timestamp at or after expiry. Both claim/refund pay their fixed address.

Use `0x` plus 64 hexadecimal digits for ETH `bytes32` hashlock/preimage inputs. The hash is **SHA-256**, not Ethereum `keccak256`. AUR's CLI prints these values without `0x`; add the prefix when passing them to an EVM wallet library. Use integer strings/BigInt for wei; never floats. Fund transaction gas separately from the locked principal. Both participant addresses must be able to sign the required transaction and accept ETH; a recipient/sender contract that rejects ETH can prevent its own payout. There is no recipient redirection or rescue administrator.

The website loads the supplied compiler artifact and checks chain ID and exact runtime bytecode before settlement. Before using valuable funds, validate amount/deadline rejection, unique IDs/nonces, correct/incorrect preimages, both authorization checks, claim/refund boundary times, double withdrawals, reverting receivers and reentrant receiver attempts. Then obtain independent review. A deployment must explicitly record the EVM chain ID, deployed address, transaction receipt, runtime bytecode/source verification and ABI. **No deployment has been performed and no contract address is provided in this release.** The current website verifies the chosen chain and bytecode before asking the connected wallet to fund a lock.

Forced ETH sent by EVM mechanisms outside `lock` is not credited to a swap and has no owner recovery path. Plain direct ETH transfers are rejected. No contract feature can prevent a counterparty's malicious behavior outside the protocol or fix Aurion consensus. The implementation and ABI are experimental artifacts for review.
