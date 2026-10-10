# Aurion backup and update tools — 2026-10-10

Additive recovery tools for the existing experimental0.2.1 protocol. The coin
source and mainnet genesis are unchanged. Existing miner ZIPs and their pinned
checksums are unchanged. These tools do not certify the protocol for valuable funds.

Save `aurion.py`, `node_backup.py` and `update_guard.py` together in a new folder.
Compare their SHA-256 hashes with this folder's `SHA256SUMS.txt`. Python3.10 or
newer is sufficient; on Windows replace `python3` with `py -3`.

Stop your miner/node and all wallet signing copies. Keep the original ledger,
wallet JSON, `.signing.sqlite` journals and the complete plots directory.
Install candidate code in a different folder, then run:

```sh
python3 node_backup.py /ABSOLUTE/old/aurion-data/aurion-mainnet.db \
  /ABSOLUTE/backups/before-update.db --network mainnet --allow-unaudited-mainnet
python3 update_guard.py /ABSOLUTE/backups/before-update.db \
  /ABSOLUTE/backups/new-rehearsal --network mainnet --allow-unaudited-mainnet \
  --current-source /ABSOLUTE/old/aurion.py \
  --candidate-source /ABSOLUTE/new/aurion.py
```

Add `--wallet /ABSOLUTE/old/aurion-wallet.json --signers-stopped` to capture an
existing matching native signing journal. Repeat `--wallet` for each wallet or
plot key. A missing or rolled-back journal is refused, never initialized. Keep
all signers stopped throughout capture. Raw plot data is not bundled; preserve
its original folder and a private copy.

The rehearsal retains a consistent ledger, both state exports, source files,
checksums and a report. It refuses changed balances, minted rewards, network
identity, transaction/checkpoint history, retained forks or signing indices.
It does not install, restore, reset data, start mining or contact a network.
Both source files must be trusted/reviewed. Code isolation is not a hostile-code
sandbox. Restore an old wallet plus old journal only after verifying its current
signing floor; whole-profile rollback and unknown independent signing cannot be
recovered from the backup alone.

Only switch to the candidate after a compatible report, and retain the same
original absolute data/plot/wallet paths. Read
[UPDATE_AND_RECOVERY.md](UPDATE_AND_RECOVERY.md) for the full procedure and
checkpoint-pinning option. Existing Cloudflare namespaces must never be reset.

Use [the website wallet](https://aurioncoin.io/wallet) for an encrypted browser
recovery backup. It preserves known used keys and saved signed AUR envelopes,
including archived attempts. Export after every signing attempt/password change.
Never publish wallet backups or passwords. Bitcoin/Ethereum extensions require
their own backups.

No paid service is activated. POSIX private file modes were tested. Native
browser crash durability and native Windows execution/ACLs remain unverified.
The qualification evidence is an internal test/review record, not an independent
cryptography audit or a backup of any user's funded data.
