#!/usr/bin/env python3
"""Interactive Aurion launcher. No wallet secrets are sent to the website."""
import json
from pathlib import Path
import subprocess
import sys
import webbrowser

ROOT = Path(__file__).resolve().parent
BASE = [sys.executable, str(ROOT / 'aurion.py'), '--network', 'mainnet', '--allow-unaudited-mainnet']

def run(*args):
    return subprocess.run(BASE + list(args), cwd=ROOT).returncode

def address():
    try:
        return json.loads((ROOT / 'aurion-wallet.json').read_text())['address']
    except (OSError, ValueError, KeyError):
        return input('Your receiving address: ').strip()

def main():
    print('Aurion — UNAUDITED EXPERIMENTAL MAINNET')
    print('Known consensus and signature weaknesses remain. No price or exchange listing is guaranteed.')
    print('Every mining node joins https://node.aurioncoin.io and validates its own ledger.')
    while True:
        print('\n1 Create encrypted wallet\n2 Create storage plot\n3 Run node and mine\n4 Network status\n5 Balance\n6 Send AUR\n7 Wallet information\n8 Self-test\n9 BTC / ETH wallets and settlement\n10 Peer conversion offers\n11 Cloud mining subscriptions\n0 Exit')
        choice = input('Choose: ').strip()
        if choice == '0': return
        if choice == '1': run('wallet', 'new', '--encrypt')
        elif choice == '2': run('plot', 'create', '--size-mb', input('Plot size in MB (start with 1): ').strip() or '1', '--reward-address', address())
        elif choice == '3': run('node', '--mine')
        elif choice == '4': run('info')
        elif choice == '5': run('balance', address())
        elif choice == '6': run('send', input('Recipient address: ').strip(), input('Amount in AUR: ').strip())
        elif choice == '7': run('wallet', 'info')
        elif choice == '8': subprocess.run([sys.executable,str(ROOT / 'aurion.py'),'selftest'],cwd=ROOT)
        elif choice == '9':
            print('Opening wallet-approved BTC / ETH tools. External wallet extensions are required.')
            print('No automatic exchange or liquidity is supplied. Ethereum CLI: python3 ethereum_swap.py --help')
            if not webbrowser.open('https://aurioncoin.io/trade'):
                print('Open https://aurioncoin.io/trade in your wallet-enabled browser.')
        elif choice == '10': subprocess.run([sys.executable,str(ROOT / 'market_client.py'),'offers'],cwd=ROOT)
        elif choice == '11':
            print('Opening cloud mining status and subscriptions. Payments require funded healthy capacity.')
            if not webbrowser.open('https://aurioncoin.io/cloud-mining'):
                print('Open https://aurioncoin.io/cloud-mining in your wallet-enabled browser.')
        else: print('Choose a listed option.')

if __name__ == '__main__':
    try: main()
    except (KeyboardInterrupt, EOFError): print('\nStopped.')
