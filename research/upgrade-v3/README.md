# Aurion offline upgrade research — 10 October 2026

**This directory cannot run an Aurion mainnet node or migrate real funds.**
It is a public review subset, separate from the current miner and published
0.2.1 binaries. The legacy runtime and release archives remain unchanged.

From `research/upgrade-v3` in this public checkout:

```sh
python3 -m venv .venv
.venv/bin/pip install -r upgrade/requirements.txt
.venv/bin/python -m unittest discover -s tests -p 'test_upgrade.py'
.venv/bin/python -m unittest discover -s tests -p 'test_consensus_candidate.py'
.venv/bin/python -m unittest discover -s tests -p 'test_mldsa_interop.py'
```

For the recorded Linux x86_64 / CPython 3.12 wheel environment, use
`pip install --require-hashes -r upgrade/requirements-linux-py312.txt`.
Interoperability requires Node with native ML-DSA-65 and FIPS-context support;
unsupported runtimes produce an explicit skip. The recorded environment used
Python 3.12.14, cryptography 50.0.1 / OpenSSL 4.0.2, chiapos 2.0.12 and
Node 24.19.0 / OpenSSL 3.5.7. Both signature APIs use OpenSSL; these are not
independent implementations or audit approval.

`upgrade/protocol.py` tests standard signatures, atomic account/key rotation,
detached authorization envelopes and rejection of incomplete or altered saved
schemas. `upgrade/consensus.py` binds real native proof bytes to signed plot
registration and checkpoint records. Its beacon is a fixed trusted fixture;
its branch score is arbitrary. Synthetic graph tests mock proof verification
and carry no native-proof attestation. Public k=18 vectors come from disposable
small plots and provide no production storage-security or retention guarantee.

`scripts/check_migration.py --help` describes the offline preservation tool.
It requires an existing hosted public-ledger backup, separately retained source
and backup hashes, genesis and selected checkpoint. Review legacy source before
pinning its hash: replay executes that exact source in memory and is not a
hostile-code sandbox. It writes a new private evidence file and never imports
balances or overwrites a wallet. Use a stable local directory without concurrent
writers. The operator backup and full hosted test suite are excluded from this
public subset; use your own independently anchored backup for preservation work.

The [public result](https://aurioncoin.io/downloads/protocol-candidate-verification-20261010.json)
records the full checkout's actual test counts and source hashes. Public files
below this directory map to the same relative `upgrade/`, `tests/` and `scripts/`
paths in that source snapshot; this README maps to `docs/OFFLINE_UPGRADE_REVIEW.md`.
The result is a local engineering observation, not external certification.

Production randomness, difficulty/finality, a reviewed legacy-ownership claim,
supported network/runtime integration, sustained hostile-network qualification,
independent review and independently operated nodes are still missing. No
activation, replacement genesis, payment handling or migration is enabled here.
