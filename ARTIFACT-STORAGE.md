# Build output storage

Store generated installers, APKs, archives, models, screenshots, reports and encrypted license bundles directly in Cloudflare R2. GitHub holds source, release metadata and build logs. Do not add GitHub artifact upload/download actions, binary release attachments or generated review binaries to repository branches.

The private `andromeda-ci-artifacts` bucket receives temporary build handoffs (90-day retention) through `https://14d.space/api/artifacts`. GitHub Actions obtains a short-lived identity token; build jobs need `permissions: id-token: write` and Node24, without permanent Cloudflare credentials. Only trusted main-branch and tag workflows can store or retrieve these private outputs. Keystores, encrypted founder keys and published release proofs use the separate private `andromeda-private-artifacts` bucket without expiry; sensitive key groups require the repository owner as the workflow actor. Pull-request builds retain their build and test checks.

Use the checked-in helper from the repository root:

```sh
node scripts/r2-artifacts.mjs upload --name package-linux --path 'dist/*.tar.gz' --path 'dist/smoke-linux.json'
node scripts/r2-artifacts.mjs download --pattern 'package-*' --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" --expected-sha "$GITHUB_SHA" --expected-count 2 --directory release --merge-multiple
```

Manifests bind the repository, source commit, workflow run and attempt to each file's size and SHA256. Uploads and downloads verify full contents. Each attempt is isolated; rerun the complete workflow when a release needs outputs from every platform. A partial rerun cannot mix earlier artifacts into a new release.

Product publishers verify package and smoke evidence before copying customer downloads to their public R2 paths, and update the latest-release manifest last. Keep customer records, keystores and encrypted license bundles in private storage. Never print license keys or private credentials into build logs.

The artifact-policy workflow checks future workflow changes for prohibited GitHub artifact and binary-release transports. Owners can also retrieve private build files from the Cloudflare R2 dashboard.
