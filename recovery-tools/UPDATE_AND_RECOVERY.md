# Updating without replacing existing funds or mining history

Website code, the hosted ledger, desktop node data and wallet signing state are
separate. Keep the existing network identity and all four Durable Object
namespaces. A new release must not create a replacement ledger or founder
wallet. The current mainnet genesis is:

`4f3347fd386cf267163dc329bd9781ef61b2915927507646d31c2584b977000d`

## Website wallet recovery

Open https://aurioncoin.io/wallet and choose **Download recovery backup**. This
works with a locked local wallet or a signed-in account. The file contains one
password-encrypted wallet, its known used-key counter, and exact saved public
AUR transfer/swap envelopes, including archived transactions. It contains no
password or decrypted seed. Export after every signing attempt and password
change; save the file offline and keep its password separately.

Restore only a file you exported yourself. Its counters are trusted metadata,
not proof that no signatures were created after export. To restore, sign out,
lock the wallet, choose the recovery file and inspect its
address/counter/history. Confirm that it is the latest backup and other
signing copies are stopped, then choose **Merge recovery into this browser**.
The wallet remains locked. Restoration preserves the current higher signing
counter and current ciphertext/password for the same identity. A different
wallet, conflicting signed transaction or wrong genesis is refused. A failed
cross-database merge can consume more keys and blocks signing until a recovery
import completes; retry the same file rather than resetting browser storage.

This restores local browser records. It does not replace a hosted account,
reset a password, change chain balances or back up Bitcoin/Ethereum extensions.
Browser and desktop copies are independent. Restoring an old backup into an
empty profile cannot discover signatures created after that backup; neither
can restoring both a desktop wallet and its signing journal. Use one current
signing location. Keep all previous files until restoration is verified.

## Desktop mining and node updates

Download the additive tools from the public miner's `recovery-tools` directory,
including its unchanged `aurion.py`, and compare the supplied SHA-256 checksums.
Python 3.10 or newer is sufficient; no packages or paid service are required.
The following commands assume the flat recovery-tools directory. In the full
source repository, use `scripts/node_backup.py` and `scripts/update_guard.py`.
On Windows use `py -3` in place of `python3`.

1. Stop the miner, node service, wallet signers and all copied signing processes.
   Preserve the original `aurion-data/`, `plots/`, encrypted wallet files and
   their `.signing.sqlite` journals. Keep the full plot directory, including
   `.dat`, metadata, private key files and any signing-journal sidecars.
2. Install candidate **code in a separate folder**. Do not unzip over your
   existing data, create a replacement wallet or replace genesis documents.
3. Make a new ledger snapshot outside the original data folder:

```sh
python3 node_backup.py /ABSOLUTE/old/aurion-data/aurion-mainnet.db \
  /ABSOLUTE/backups/before-update.db --network mainnet --allow-unaudited-mainnet
```

4. Rehearse both versions against that immutable backup:

```sh
python3 update_guard.py /ABSOLUTE/backups/before-update.db \
  /ABSOLUTE/backups/update-rehearsal --network mainnet --allow-unaudited-mainnet \
  --current-source /ABSOLUTE/old/aurion.py \
  --candidate-source /ABSOLUTE/new/aurion.py \
  --wallet /ABSOLUTE/old/aurion-wallet.json --signers-stopped
```

Use fresh backup/output paths each time. Repeat `--wallet` for each wallet or
plot key JSON whose signing journal must be preserved. The guard does not copy
large plot data; keep its original stopped directory and a separate private
copy. A missing wallet `.signing.sqlite` refuses capture rather than inferring that
no keys were used. Preserve the original wallet and use its current signing
location; do not remove or recreate a journal to make the check pass.

The report must say compatible before switching. It compares network
parameters, genesis, every retained checkpoint branch, balances, total minted
rewards, HTLCs, receipts, used indices and the complete transaction DAG. It
retains private-mode backup files, state exports, source hashes and checksums;
it does not start software, overwrite originals or restore signing state.
POSIX file modes 0600 and directories 0700 are verified. On Windows, use a
private output folder with suitable access permissions; native Windows ACLs
and execution have not been verified. Live SQLite backup can update transient
reader-lock metadata in `-shm`, while preserving ledger database/WAL contents.
Candidate code runs during replay, so use a reviewed source from a trusted
release. A rehearsal is not a sandbox or a security audit.

If you have a separately trusted retained checkpoint, supply
`--expected-best HASH --expected-height NUMBER` together to bind the rehearsal
to it. Obtain these from your own prior record or an independently verified
node, not just the backup being tested. Without that external reference, a
whole-backup rollback cannot be detected.

5. Start the candidate node against the **same original absolute paths**:

```sh
python3 /ABSOLUTE/new/aurion.py --network mainnet --allow-unaudited-mainnet \
  node --mine --datadir /ABSOLUTE/old/aurion-data --plots /ABSOLUTE/old/plots
```

Keep the wallet at its original path for future sends. Check the expected
address, genesis, height and known transaction receipts before resuming
signing. Retain the old code and backups. If a candidate fails, stop it first;
replay the newest ledger against the previous code before rolling back. Never
copy an older wallet/journal back to reclaim signing capacity.

## Hosted website updates

Routine website updates use the Worker's **content-only** endpoint. Preserve
namespace IDs, class names, object-name derivation, bindings, secrets and
runtime configuration. A change to stored-data modules, namespace identities
or consensus needs a separately reviewed migration and restoration rehearsal.
No ordinary website update resets mining rewards or replaces the hosted seed.

`scripts/prepare_deployment.py` creates a code-only payload with hashes and a
new private-mode output file. It never reads founder credentials or billing
configuration, and refuses existing output paths and symlinked build sources.
It is a preparation step; it does not verify live storage or deploy anything.
Run the updater with a token privately configured on your own machine:

```sh
node scripts/deploy.mjs --dry-run
```

A token-free run checks only the local build and explicitly reports that live
bindings were not verified. A live dry-run checks existing settings/namespaces,
all server modules, coin/genesis pins and the active immutable version. Use its
reviewed hashes to run the actual update, replacing the two hash placeholders:

```sh
node scripts/deploy.mjs --expected-base-hash REVIEWED_BASE_HASH \
  --expected-settings-hash REVIEWED_SETTINGS_HASH \
  --report .private/site-update-new.jsonl
```

Use a new report path. The updater creates an exclusive private append-only
rollback journal before uploading, rechecks the live base and then verifies
every module, settings and the new version at 100% traffic. Coordinate updates
so only one deployer runs at a time; the provider's content endpoint has no
confirmed atomic configuration/version precondition. Existing report paths,
server/storage module changes or runtime/binding changes are refused. The
journal records the previous immutable version and a code rollback command.
Rolling back code does not roll back the ledger or signing journals.

The provider's hosted storage and native SQLite files are different systems.
A namespace/version reference is not a ledger export. Never delete/recreate
production Durable Objects or use point-in-time restoration to rewind signing
state: restoring an account counter behind a published signature may reuse a
key. Public node history can be replayed; private account/market storage needs
a provider-supported recovery procedure with counter and transaction-history
checks. Do not publish private account rows, wallet backups or credentials.

## What these checks establish

They test preservation against the supplied history and protect known local
signing counters. They do not repair the current legacy protocol's documented
consensus/signature weaknesses or guarantee that funds cannot be lost. No
paid hosting, audit, miner or subscription is activated by the tools. Keep
backups outside the machine/provider's failure domain and verify restoration
before discarding originals.
