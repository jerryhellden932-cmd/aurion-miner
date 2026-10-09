# Persistent independent-node operation

The observed hosted seed is `https://node.aurioncoin.io`. A second process owned
by the same person does not establish independent operation. No external node
operator, funded server or multi-day uptime claim is supplied by this release.

In the flat public miner download, run `python3 node_backup.py` and
`python3 network_health.py` without the `scripts/` prefix shown below.
The systemd template is supplied in the full source repository.

The repository includes a systemd service in `infrastructure/node/` for a
non-mining validating node. It uses an unprivileged `aurion` user, private state
directory, loopback HTTP, restart policy and resource limits. An operator must
place the pinned source under `/opt/aurion`, create the service account and
install the unit on an authorized Linux host. Inspect and adapt memory limits
to measured ledger growth. Do not place wallet keys on validating-only nodes.

The service does not mine or purchase hosting. An eligible miner must remain
online to advance the current network; a running seed alone cannot do that.
To expose a node, configure TLS/firewall/rate limiting and explicit public peer
addresses. Automatic peer discovery admits public literal IPs and the fixed
seed only; DNS and private-network peers require operator configuration.
Redirects are refused. Do not expose private metadata or management endpoints.

## Monitor

```sh
python3 scripts/network_health.py --peer https://node.aurioncoin.io \
  --genesis 4f3347fd386cf267163dc329bd9781ef61b2915927507646d31c2584b977000d
```

Repeat `--peer` for each verified operator. Exit code 1 reports failures, stale
checkpoints, missing freshness information or disagreeing tips. A transient tip
difference can be normal while a block propagates; inspect it before declaring
a fault. Endpoint agreement alone does not prove separate operators or finality.
Schedule this with the operator's existing monitoring service after deployment.

## Back up and rehearse restoration

```sh
python3 scripts/node_backup.py /var/lib/aurion/aurion-mainnet.db \
  /secure-backups/aurion-20261009.db --network mainnet --allow-unaudited-mainnet
python3 scripts/node_backup.py /secure-backups/aurion-20261009.db \
  --verify-only --network mainnet --allow-unaudited-mainnet
```

SQLite's backup API creates a consistent copy while the node runs. Validation
replays a temporary copy and records genesis, tip, height and SHA-256 in a
manifest. Existing destinations are never overwritten. This backs up public
ledger data only. Store backup manifests outside the node's failure domain.

Restore to a **new** directory, compare genesis/tip with independently operated
peers, resynchronize and verify known receipts before switching service. Keep
the previous directory until recovery is proven. Do not reset or recreate
production Durable Object namespaces. Use the provider's supported recovery
procedure for the hosted seed/account database; this tool handles native-node
SQLite files, not Cloudflare storage exports.

## Legacy wallet recovery limitation

The `.signing.sqlite` sidecar maintains a high-water mark when only an older
wallet JSON is restored at the same path. Local signing tickets are single-use.
Keep the sidecar with the current wallet; never remove it to recover signing
capacity. Failed saves can burn a slot, deliberately. The journal does not
protect copied files, other devices or restoration of both wallet and journal.
Use one current signing location; independent node operators need no user keys.

Before a multi-operator readiness claim, record each operator's consent,
separate administrative control, provider/region, source commit and endpoint
in a private operator inventory; publish only consented public metadata.
Collect sustained uptime/chain progress and dated partition/rejoin, restore and
upgrade exercises. A deployment template is not evidence those exercises ran.
