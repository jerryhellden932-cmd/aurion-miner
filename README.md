# Aurion desktop miner 0.2.1

Aurion is an **unaudited experimental mainnet** with known consensus and
signature weaknesses. It is not proven quantum resistant or ready to protect
valuable funds. Mining rewards may be zero, and no buyer, price, liquidity,
exchange listing, or Bitcoin/Ethereum conversion is guaranteed. Read
[SECURITY.md](SECURITY.md) before joining.

## Download and start mining

1. Install Python **3.10 or newer** from https://www.python.org/downloads/.
   On Windows, enable the Python launcher during installation. No additional
   Python packages are required.
2. Download the ZIP for your operating system and extract it into a writable
   folder. Do not run the program directly inside the ZIP archive.
3. Start the launcher:
   - **Windows:** double-click `Aurion.cmd`, or run `py -3 launcher.py`.
   - **Linux:** run `bash Aurion.sh`, or `python3 launcher.py`.
   - **macOS:** run `bash Aurion.command`, or `python3 launcher.py`.
4. Choose **1** to create an encrypted wallet and keep its password private.
   Choose **2** to create a plot, starting with 1 MB. Choose **3** to run your
   node and mine. Keep it running; press **Ctrl+C** to stop.

Once the network has mature plots, a new plot must be included and wait three
checkpoints before it can mine. An existing eligible miner must keep advancing
the chain during that wait. If the network height is stalled, leave your node
connected and check network status; starting the software alone does not mean
that a mining reward has been earned.

If you already have a wallet at https://aurioncoin.io, export its **current**
`aurion-wallet.json` into the extracted folder and **skip option 1**. Never
replace that wallet by creating a different one. Use one current signing
location: avoid signing from the website and desktop concurrently, from old
exports, copied wallets, or restored backups. Wallets have 1,024 one-time
signing slots; reusing a signing slot can compromise funds. Plot signing keys
also expire and require replacement plots. Wallet encryption does not prevent
one-time signing-key reuse. Release 0.2.1 adds a `.signing.sqlite` high-water
journal at the wallet path; keep it intact. It protects restoration of only the
JSON at that location, not copies or restoration of both files. Failed saves
can deliberately burn slots. NODE_OPERATIONS.md covers backup and monitoring.

Your miner keeps its own ledger, validates checkpoints independently, and
automatically joins the seed https://node.aurioncoin.io. The default local node
binds to loopback. Publishing a peer requires your own network/HTTPS setup;
mining does not require exposing a port. This release does not include a paid
cloud-mining worker, hosting account, subscription provisioning, or operator
credentials. Do not run miners on GitHub Actions or a host that prohibits them.

## Commands and transfers

Use `py -3` instead of `python3` on Windows. Global options precede the command:

```sh
python3 aurion.py selftest
python3 aurion.py --network mainnet --allow-unaudited-mainnet info
python3 aurion.py --network mainnet --allow-unaudited-mainnet balance YOUR_ADDRESS
python3 aurion.py --network mainnet --allow-unaudited-mainnet send RECIPIENT_ADDRESS 1
```

The launcher acknowledges the experimental mainnet flag. It does not make the
network secure. Wallet files, passwords, private keys, plots, and ledger state
must remain private and must never be uploaded to a public repository.

## Trading tools

Launcher option 9 opens https://aurioncoin.io/trade for external BTC/ETH wallet
tools. Option 10 lists user-priced conversion offers through `market_client.py`.
Offer matching reserves metadata, not funds: trades need willing counterparties,
wallet approval, and verified chain transactions. Bitcoin HTLC settlement is
manual. Ethereum swaps require a deployed compatible contract and ETH gas;
including an ABI/artifact does not mean a contract is deployed. Read TRADE.md,
MARKET.md, and ETHEREUM.md. The exchange API adapter and client are included for
integration review; see EXCHANGE.md. They are not an exchange listing.

Launcher option 11 opens the website's cloud-mining status page. Paid cloud
mining and subscription provisioning remain disabled until separately funded
capacity and eligible payment processing exist.

## Release identity and integrity

`genesis.json` and `genesis-config.json` publish the network identity, seed,
21-million-AUR maximum supply, and founder's 21,000-AUR genesis allocation.
`release-manifest.json` records release identity and SHA-256 hashes of the
desktop files and ZIPs. `SHA256SUMS.txt` covers every other published file,
including the manifest. Hashes detect changed bytes; they are not a developer
signature or evidence of cryptographic/consensus security.

To check the archive, compare its SHA-256 with SHA256SUMS.txt obtained from the
same pinned release commit. Linux: `sha256sum aurion-linux.zip`; macOS:
`shasum -a 256 aurion-macos.zip`; Windows PowerShell:
`Get-FileHash .\aurion-windows.zip -Algorithm SHA256`.

These are Python source distributions, not standalone native installers. The
complete private website/backend project is intentionally absent from this
public desktop release.
