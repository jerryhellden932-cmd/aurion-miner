#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AURION (AUR) - experimental reference implementation in a single file
=========================================================
Node, wallet, storage miner (Proof of Verifiable Contribution), DAG ledger,
post-quantum signatures and AUR<->BTC atomic-swap tooling.

Pure Python 3.9+ standard library. No external dependencies.

Design (Aurion design paper v0.1)
---------------------------------
  * Ledger ....... a DAG of transactions. Every transaction approves 1-2
                   earlier transactions. Periodic checkpoints give the DAG a
                   deterministic total order and finality.
  * Consensus .... Proof of Verifiable Contribution (PoVC): contributors
                   dedicate disk space as "plots". Each checkpoint round has a
                   public challenge; the plot holding the closest stored value
                   wins the right to produce the checkpoint and the reward.
                   Chance of winning is proportional to storage contributed.
  * Signatures ... hash-based (WOTS + Merkle tree, XMSS-style), believed
                   secure against quantum computers. Each address can sign
                   2^height times (default 1024); the wallet warns before
                   that runs out so you can move funds to a fresh address.
  * Supply ....... hard cap 21,000,000 AUR. A 0.10 % founder allocation is
                   written into the genesis checkpoint, published in this file
                   and available from genesis. The remaining 99.9 % is
                   issued to miners with Bitcoin-style halvings.
  * Swaps ........ hash-time-locked contracts (HTLCs) on Aurion plus a
                   matching Bitcoin P2WSH HTLC script generator, for
                   trustless peer-to-peer AUR<->BTC trades.

STATUS: unaudited experimental network software with known consensus flaws.
Mainnet requires explicit --allow-unaudited-mainnet acknowledgement. This flag
does not make the implementation secure or suitable for storing real value.
Test coins have no assigned monetary value.
The custom hash-based signature scheme is not a quantum-proof guarantee.
Known limitations are listed at the bottom of this file.

Quick start
-----------
  python3 aurion.py selftest                           # built-in test suite
  python3 aurion.py --network testnet wallet new       # create a wallet
  python3 aurion.py --network testnet plot create --size-mb 100 --reward-address <aur...>
  python3 aurion.py --network testnet node --mine      # run a node and mine
  python3 aurion.py --network testnet balance <aur...>
  python3 aurion.py --network testnet send <to> <amount>
  python3 aurion.py swap --help                        # atomic-swap tools

Repeatable local experiment
---------------------------
  python3 aurion.py --network regtest wallet new --file demo-wallet.json
  python3 aurion.py --network regtest plot create --size-mb 1 --reward-address <aur...>
  python3 aurion.py --network regtest node --mine --bind 127.0.0.1
  python3 aurion.py --network regtest balance <aur...>

Experimental mainnet (explicit risk acknowledgement required)
------------------------------------------------------------
  python3 aurion.py --network mainnet --allow-unaudited-mainnet wallet new --file wallet.json
  python3 aurion.py --network mainnet --allow-unaudited-mainnet plot create --size-mb 100 --reward-address <aur...>
  python3 aurion.py --network mainnet --allow-unaudited-mainnet node --mine
  python3 aurion.py --network mainnet --allow-unaudited-mainnet balance <aur...>

Mainnet clients use https://node.aurioncoin.io by default. Mining nodes keep
their own local ledger and discover the public seed unless --peer is supplied.
Consensus redesign, a reviewed post-quantum implementation, independent audits
and release engineering remain necessary before this can be considered secure.
"""

import argparse
import contextlib
import decimal
import getpass
import hashlib
import heapq
import hmac
import ipaddress
import json
import math
import mmap
import os
import re
import secrets
import shutil
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "0.2.1-experimental"
DEFAULT_MAINNET_NODE = "https://node.aurioncoin.io"

# =============================================================================
# 1. MONETARY POLICY  (consensus-critical: every node must use the same values)
# =============================================================================
COIN = 100_000_000                       # 1 AUR = 100,000,000 base units
MAX_SUPPLY = 21_000_000 * COIN           # hard cap

# ---- Founder allocation -----------------------------------------------------
# A fixed, public share of the supply credited to the founder in the genesis
# checkpoint. Anyone reading this file or querying a node can see the amount,
# the address and allocation. The intended allocation is available from genesis;
# the experimental mainnet requires explicit acknowledgement of known risks.
FOUNDER_ADDRESS = "aur285360486e19a68d23e4ff2645eb7856bf5f14c8868164c9d6ee6c7c9f533796"
FOUNDER_ALLOCATION_BPS = 10              # basis points: 10 = 0.10 % = 21,000 AUR
FOUNDER_ALLOCATION = MAX_SUPPLY * FOUNDER_ALLOCATION_BPS // 10_000
MINING_SUPPLY = MAX_SUPPLY - FOUNDER_ALLOCATION
MAINNET_GENESIS_TIME = 1791495239         # published experimental genesis Unix time

# ---- Consensus constants ----------------------------------------------------
MIN_FEE = 1_000                          # 0.00001 AUR
TX_MAX_AGE = 3600                        # seconds a tx may wait for a checkpoint
MAX_DRIFT = 120                          # allowed clock skew, seconds
MAX_TXS_PER_CHECKPOINT = 5_000
MAX_TIPS = 64
REG_DELAY = 3                            # checkpoints before a new plot may win
PLOT_K = 16                              # hash iterations per plot entry
REORG_LIMIT = 100                        # checkpoints; deeper history is final
WALLET_HEIGHT = 10                       # 2^10 = 1024 signatures per address
GENESIS_REF = "0" * 64

ADDR_RE = re.compile(r"^aur[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")


class Params:
    """Per-network parameters."""

    def __init__(self, name, port, interval, halving, vesting, genesis_time,
                 founder, pow_bits, btc_hrp):
        self.name = name
        self.port = port
        self.interval = interval          # target seconds between checkpoints
        self.halving = halving            # checkpoints per halving epoch
        self.vesting = vesting            # checkpoints for founder vesting
        self.genesis_time = genesis_time
        self.founder = founder
        self.pow_bits = pow_bits          # anti-spam work for free plot registration
        self.btc_hrp = btc_hrp
        self.r0 = MINING_SUPPLY // (2 * halving)

    def reward(self, h):
        if h < 1:
            return 0
        epoch = (h - 1) // self.halving
        return self.r0 >> epoch if epoch < 64 else 0

    def locked(self, addr, h):
        """Founder tokens still locked at checkpoint height h."""
        if not self.founder or addr != self.founder or self.vesting <= 0 or h >= self.vesting:
            return 0
        return FOUNDER_ALLOCATION * (self.vesting - max(h, 0)) // self.vesting


def make_params(network, founder=None, allow_unaudited_mainnet=False):
    if network == "mainnet":
        if not allow_unaudited_mainnet:
            sys.exit("Mainnet is disabled unless --allow-unaudited-mainnet is supplied. "
                     "Aurion 0.2.0-experimental has known consensus flaws and unaudited "
                     "stateful signatures; it is not quantum-proof or secure for real value. "
                     "Use --network regtest for local experiments or --network testnet "
                     "for test coins.")
        if (not isinstance(FOUNDER_ADDRESS, str) or not ADDR_RE.fullmatch(FOUNDER_ADDRESS)
                or type(MAINNET_GENESIS_TIME) is not int or MAINNET_GENESIS_TIME <= 0):
            sys.exit("Experimental mainnet genesis is not configured: the release must "
                     "publish a valid FOUNDER_ADDRESS and positive MAINNET_GENESIS_TIME.")
        return Params("aurion-mainnet", 7333, 60, 2_100_000, 0,
                      MAINNET_GENESIS_TIME, FOUNDER_ADDRESS, 20, "bc")
    if network == "testnet":
        return Params("aurion-testnet", 17333, 15, 210_000, 0,
                      1_790_000_000, founder or "", 16, "tb")
    if network == "regtest":
        return Params("aurion-regtest", 27333, 0, 100, 0,
                      1_790_000_000, founder or "", 4, "bcrt")
    raise ValueError("unknown network " + network)


def fmt(units):
    sign = "-" if units < 0 else ""
    units = abs(units)
    return f"{sign}{units // COIN:,}.{units % COIN:08d} AUR"


def parse_amount(s):
    try:
        d = decimal.Decimal(s)
    except (decimal.InvalidOperation, TypeError, ValueError):
        raise ValueError(f"not a number: {s}")
    if not d.is_finite() or d <= 0 or d > MAX_SUPPLY // COIN:
        raise ValueError("amount must be finite, positive and at most 21,000,000 AUR")
    with decimal.localcontext() as ctx:
        ctx.prec = max(28, len(d.as_tuple().digits) + 8)
        units = d * COIN
        if units != units.to_integral_value() or units <= 0:
            raise ValueError("amount must be positive with at most 8 decimals")
    return int(units)


def parse_plot_size(value):
    """Reject invalid sizes before creating directories or wallet keys."""
    try:
        size = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("plot size must be a finite, positive number of MB")
    if not math.isfinite(size) or size <= 0:
        raise ValueError("plot size must be a finite, positive number of MB")
    if size > 1024:
        raise ValueError("max 1024 MB per plot; create several plots for more space")
    return size


def cli_plot_size(value):
    try:
        return parse_plot_size(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def cli_amount(value):
    try:
        return parse_amount(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


# =============================================================================
# 2. POST-QUANTUM SIGNATURES (WOTS + Merkle tree, hash-based)
# =============================================================================
def H(*parts):
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


W = 16
LEN1 = 64
LEN2 = 3
LEN = LEN1 + LEN2


def _digits(msg32):
    d = []
    for b in msg32:
        d.append(b >> 4)
        d.append(b & 15)
    cs = sum(W - 1 - x for x in d)
    d += [(cs >> 8) & 15, (cs >> 4) & 15, cs & 15]
    return d


def _chain(x, start, steps, pub_seed, leaf, ci):
    sha = hashlib.sha3_256
    pre = b"C" + pub_seed + struct.pack(">IH", leaf, ci)
    for i in range(start, start + steps):
        x = sha(pre + bytes([i]) + x).digest()
    return x


def _wots_sk(seed, leaf, ci):
    return H(b"S", seed, struct.pack(">IH", leaf, ci))


def _wots_pk(seed, pub_seed, leaf):
    ends = [_chain(_wots_sk(seed, leaf, ci), 0, W - 1, pub_seed, leaf, ci)
            for ci in range(LEN)]
    return H(b"P", pub_seed, struct.pack(">I", leaf), *ends)


def _node(pub_seed, level, idx, left, right):
    return H(b"N", pub_seed, struct.pack(">BI", level, idx), left, right)


def _msg_digest(pub_seed, leaf, msg):
    return H(b"M", pub_seed, struct.pack(">I", leaf), msg)


def address_from(pub_seed, root):
    return "aur" + H(b"A", pub_seed, root).hex()


class MerkleKey:
    def __init__(self, seed, pub_seed, height, leaves=None, progress=False):
        self.seed, self.pub_seed, self.height = seed, pub_seed, height
        n = 1 << height
        if leaves is None:
            leaves = []
            for i in range(n):
                leaves.append(_wots_pk(seed, pub_seed, i))
                if progress and (i + 1) % 64 == 0:
                    print(f"\r  generating keys {i + 1}/{n}", end="", flush=True)
            if progress:
                print()
        self.levels = [list(leaves)]
        for lvl in range(height):
            prev = self.levels[-1]
            self.levels.append([_node(pub_seed, lvl + 1, j, prev[2 * j], prev[2 * j + 1])
                                for j in range(len(prev) // 2)])
        self.root = self.levels[-1][0]
        self.address = address_from(pub_seed, self.root)

    def sign(self, msg, idx):
        if not 0 <= idx < (1 << self.height):
            raise ValueError("signature index out of range")
        d = _digits(_msg_digest(self.pub_seed, idx, msg))
        parts = b"".join(_chain(_wots_sk(self.seed, idx, i), 0, d[i], self.pub_seed, idx, i)
                         for i in range(LEN))
        path = b"".join(self.levels[l][(idx >> l) ^ 1] for l in range(self.height))
        return (self.pub_seed + struct.pack(">I", idx) + parts + path).hex()


def verify_sig(address, msg, sighex):
    """Returns the signature index if valid for `address`, else None."""
    if not isinstance(sighex, str) or len(sighex) > 20_000:
        return None
    try:
        raw = bytes.fromhex(sighex)
    except (ValueError, TypeError):
        return None
    base = 36 + LEN * 32
    if len(raw) <= base or (len(raw) - base) % 32:
        return None
    pub_seed, idx = raw[:32], struct.unpack(">I", raw[32:36])[0]
    parts, path = raw[36:base], raw[base:]
    height = len(path) // 32
    if height > 20 or idx >= (1 << height):
        return None
    d = _digits(_msg_digest(pub_seed, idx, msg))
    ends = [_chain(parts[i * 32:(i + 1) * 32], d[i], W - 1 - d[i], pub_seed, idx, i)
            for i in range(LEN)]
    node = H(b"P", pub_seed, struct.pack(">I", idx), *ends)
    pos = idx
    for lvl in range(height):
        sib = path[lvl * 32:(lvl + 1) * 32]
        node = (_node(pub_seed, lvl + 1, pos >> 1, sib, node) if pos & 1
                else _node(pub_seed, lvl + 1, pos >> 1, node, sib))
        pos >>= 1
    return idx if address_from(pub_seed, node) == address else None


# =============================================================================
# 3. WALLET FILES (optional password encryption: scrypt + SHAKE-256 + HMAC)
# =============================================================================
def _kdf(password, salt):
    k = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 15, r=8, p=1,
                       maxmem=2 ** 26, dklen=64)
    return k[:32], k[32:]


def encrypt_seed(seed, password):
    salt, nonce = os.urandom(16), os.urandom(16)
    ke, km = _kdf(password, salt)
    ks = hashlib.shake_256(ke + nonce).digest(len(seed))
    ct = bytes(a ^ b for a, b in zip(seed, ks))
    tag = hmac.new(km, salt + nonce + ct, hashlib.sha3_256).hexdigest()
    return {"salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex(), "tag": tag}


def decrypt_seed(enc, password):
    salt, nonce, ct = (bytes.fromhex(enc[k]) for k in ("salt", "nonce", "ct"))
    ke, km = _kdf(password, salt)
    tag = hmac.new(km, salt + nonce + ct, hashlib.sha3_256).hexdigest()
    if not hmac.compare_digest(tag, enc["tag"]):
        raise ValueError("wrong password")
    ks = hashlib.shake_256(ke + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


class WalletExhausted(Exception):
    pass


@contextlib.contextmanager
def wallet_lock(path):
    """Process lock shared by every wallet writer on this computer.

    The lock file is permanent: unlinking it could let a second writer lock
    a different inode while the first writer still holds the old one.
    This does not synchronize separate copies, devices or restored backups.
    """
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path + ".lock", flags, 0o600)
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        acquired = True
        yield
    finally:
        if acquired:
            if os.name == "nt":
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class Wallet:
    def __init__(self, path, key, data):
        self.path = os.path.realpath(os.path.abspath(os.fspath(path)))
        self.key, self.data = key, data
        self._reserved_indices = set()

    @property
    def address(self):
        return self.key.address

    @property
    def capacity(self):
        return 1 << self.key.height

    @classmethod
    def create(cls, path, height=WALLET_HEIGHT, password=None, progress=True):
        path = os.path.realpath(os.path.abspath(os.fspath(path)))
        if os.path.exists(path):
            raise FileExistsError(f"{path} already exists, refusing to overwrite")
        if type(height) is not int or not 1 <= height <= 20:
            raise ValueError("wallet height must be an integer between 1 and 20")
        seed, pub_seed = secrets.token_bytes(32), secrets.token_bytes(32)
        key = MerkleKey(seed, pub_seed, height, progress=progress)
        data = {"type": "aurion-wallet", "v": 1, "height": height,
                "address": key.address, "pub_seed": pub_seed.hex(),
                "leaves": [x.hex() for x in key.levels[0]], "next_index": 0}
        if password:
            data["enc"] = encrypt_seed(seed, password)
        else:
            data["seed"] = seed.hex()
        w = cls(path, key, data)
        with wallet_lock(w.path):
            if os.path.exists(w.path):
                raise FileExistsError(f"{path} already exists, refusing to overwrite")
            w._write_data(data)
        return w

    @classmethod
    def load(cls, path, password=None):
        path = os.path.realpath(os.path.abspath(os.fspath(path)))
        with open(path) as f:
            data = json.load(f)
        if data.get("type") != "aurion-wallet" or data.get("v") != 1:
            raise ValueError(f"{path} is not an Aurion wallet")
        height = data.get("height")
        if type(height) is not int or not 1 <= height <= 20:
            raise ValueError("wallet height must be an integer between 1 and 20")
        if (type(data.get("next_index")) is not int
                or not 0 <= data["next_index"] <= 1 << height):
            raise ValueError("wallet signature counter is invalid")
        if not isinstance(data.get("leaves"), list) or len(data["leaves"]) != 1 << height:
            raise ValueError("wallet leaf count does not match its height")
        if "enc" in data:
            if password is None:
                password = getpass.getpass(f"Password for {path}: ")
            seed = decrypt_seed(data["enc"], password)
        else:
            seed = bytes.fromhex(data["seed"])
        key = MerkleKey(seed, bytes.fromhex(data["pub_seed"]), data["height"],
                        leaves=[bytes.fromhex(x) for x in data["leaves"]])
        if key.address != data["address"]:
            raise ValueError("wallet file is corrupted (address mismatch)")
        return cls(path, key, data)

    def _read_current(self):
        with open(self.path) as f:
            current = json.load(f)
        if not isinstance(current, dict):
            raise ValueError("wallet file is invalid")
        # Never let a stale object sign after its file is replaced by another key.
        identity = ("type", "v", "height", "address", "pub_seed", "leaves", "seed", "enc")
        if any(current.get(k) != self.data.get(k) for k in identity):
            raise ValueError("wallet file changed identity; reload the wallet before signing")
        counter = current.get("next_index")
        if type(counter) is not int or not 0 <= counter <= self.capacity:
            raise ValueError("wallet signature counter is invalid")
        return current

    def _write_data(self, data):
        """Atomically replace using a unique private file in the same directory."""
        folder = os.path.dirname(self.path)
        fd, tmp = tempfile.mkstemp(prefix=".aurion-wallet-", suffix=".tmp", dir=folder)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            if os.name != "nt":
                dfd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def save(self):
        with wallet_lock(self.path):
            current = self._read_current()
            counter = self.data.get("next_index")
            if type(counter) is not int or not 0 <= counter <= self.capacity:
                raise ValueError("wallet signature counter is invalid")
            current["next_index"] = max(counter, current["next_index"])
            self._write_data(current)
            self.data = current

    def reserve_index(self, chain_last=-1):
        """Durably reserve under the shared-file lock before a signature is made."""
        if type(chain_last) is not int or chain_last < -1:
            raise ValueError("last signature index must be an integer of at least -1")
        with wallet_lock(self.path):
            current = self._read_current()
            idx = max(current["next_index"], self.data["next_index"], chain_last + 1)
            # This independent high-water mark survives restoration of only the
            # wallet JSON at this path. Whole-directory rollback/copies remain
            # unsafe for legacy one-time keys. A failed file write burns a slot.
            journal = self.path + ".signing.sqlite"
            fd = os.open(journal, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
            with contextlib.closing(sqlite3.connect(journal)) as db:
                db.execute("PRAGMA synchronous=FULL")
                db.execute("CREATE TABLE IF NOT EXISTS signing (address TEXT PRIMARY KEY, next_index INTEGER NOT NULL)")
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT next_index FROM signing WHERE address=?", (self.address,)).fetchone()
                if row is not None:
                    if type(row[0]) is not int or not 0 <= row[0] <= self.capacity:
                        raise ValueError("signing journal is corrupt; do not reset it")
                    idx = max(idx, row[0])
                if idx < self.capacity:
                    db.execute("INSERT OR REPLACE INTO signing VALUES (?,?)", (self.address, idx + 1))
                db.commit()
            if idx >= self.capacity:
                self.data = current
                raise WalletExhausted("this address has used all its signatures; "
                                      "create a new wallet and move funds")
            current["next_index"] = idx + 1
            self._write_data(current)
            self.data = current
            self._reserved_indices.add(idx)
        remaining = self.capacity - idx - 1
        if remaining <= 32 and self.capacity >= 256:
            print(f"WARNING: only {remaining} signatures left for {self.address}. "
                  "Move funds to a new wallet soon.", file=sys.stderr)
        return idx

    def sign(self, msg, idx):
        with wallet_lock(self.path):
            self._read_current()
            if idx not in self._reserved_indices:
                raise ValueError("reserve a fresh signing index in this process before signing")
            # Consume before cryptography: exceptions never permit key reuse.
            self._reserved_indices.remove(idx)
        return self.key.sign(msg, idx)


# =============================================================================
# 4. STORAGE PLOTS (Proof of Verifiable Contribution)
# =============================================================================
def plot_id_for(owner, key_addr, nonce):
    return H(b"PLOT", owner.encode(), key_addr.encode(), struct.pack(">Q", nonce)).hex()


def plot_leaf(plot_id, i, k=PLOT_K):
    sha = hashlib.sha3_256
    x = sha(b"L" + plot_id + struct.pack(">Q", i)).digest()
    for _ in range(k - 1):
        x = sha(b"L" + x).digest()
    return x


def next_challenge(st):
    return H(b"CH", bytes.fromhex(st.challenge), bytes.fromhex(st.leaf)).hex()


def create_plot(plot_dir, owner, size_mb, progress=True):
    if not ADDR_RE.match(owner):
        raise ValueError("reward address must look like aur<64 hex>")
    size_mb = parse_plot_size(size_mb)
    os.makedirs(plot_dir, exist_ok=True)
    n = max(1000, min(int(size_mb * 1024 * 1024) // 36, 2 ** 32 - 1))
    tmp_key = os.path.join(plot_dir, f"pending-{secrets.token_hex(4)}.key.json")
    key = Wallet.create(tmp_key, progress=progress)
    nonce = secrets.randbits(63)
    pid_hex = plot_id_for(owner, key.address, nonce)
    pid = bytes.fromhex(pid_hex)
    entries = []
    t0 = time.time()
    for i in range(n):
        entries.append(plot_leaf(pid, i) + struct.pack(">I", i))
        if progress and (i + 1) % 50_000 == 0:
            rate = (i + 1) / (time.time() - t0)
            print(f"\r  plotting {i + 1:,}/{n:,}  (~{(n - i - 1) / rate:.0f}s left)",
                  end="", flush=True)
    if progress:
        print("\n  sorting...")
    entries.sort()
    key_file, data_file = f"{pid_hex}.key.json", f"{pid_hex}.dat"
    with open(os.path.join(plot_dir, data_file), "wb") as f:
        for e in entries:
            f.write(e)
    os.replace(tmp_key, os.path.join(plot_dir, key_file))
    meta = {"plot_id": pid_hex, "owner": owner, "nonce": nonce, "n": n,
            "key_file": key_file, "data_file": data_file, "key_address": key.address}
    with open(os.path.join(plot_dir, f"{pid_hex}.json"), "w") as f:
        json.dump(meta, f, indent=1)
    return os.path.join(plot_dir, f"{pid_hex}.json")


class LocalPlot:
    def __init__(self, meta_path):
        d = os.path.dirname(meta_path)
        with open(meta_path) as f:
            self.meta = json.load(f)
        self.plot_id = self.meta["plot_id"]
        self.key = Wallet.load(os.path.join(d, self.meta["key_file"]))
        self._f = open(os.path.join(d, self.meta["data_file"]), "rb")
        self.mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self.n = len(self.mm) // 36

    def lookup(self, chal_hex):
        """Stored entry closest at-or-above the challenge (wrapping)."""
        chal = bytes.fromhex(chal_hex)
        lo, hi = 0, self.n
        while lo < hi:
            mid = (lo + hi) // 2
            if self.mm[mid * 36:mid * 36 + 32] < chal:
                lo = mid + 1
            else:
                hi = mid
        if lo == self.n:
            lo = 0
        rec = self.mm[lo * 36:lo * 36 + 36]
        leaf = rec[:32].hex()
        return struct.unpack(">I", rec[32:])[0], leaf, (int(leaf, 16) - int(chal_hex, 16)) % (1 << 256)


def load_plots(plot_dir):
    out = []
    if os.path.isdir(plot_dir):
        for name in sorted(os.listdir(plot_dir)):
            if name.endswith(".json") and not name.endswith(".key.json"):
                out.append(LocalPlot(os.path.join(plot_dir, name)))
    return out


# =============================================================================
# 5. TRANSACTIONS, CHECKPOINTS AND LEDGER STATE
# =============================================================================
TX_KEYS = {"net", "type", "from", "to", "amount", "fee", "idx", "parents", "time", "data"}
TX_TYPES = {"transfer", "register_plot", "htlc_lock", "htlc_claim", "htlc_refund"}
CP_KEYS = {"net", "height", "prev", "time", "challenge", "proof", "tips", "producer", "idx"}


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def tx_id(tx):
    return H(b"TX", canon(tx["body"])).hex()


def cp_hash(cp):
    return H(b"CP", canon(cp["body"])).hex()


def leading_zero_bits(hexs):
    return 256 - int(hexs, 16).bit_length()


def _is_uint(x, maxv=2 ** 63):
    return type(x) is int and 0 <= x < maxv


def check_tx_form(p, tx):
    try:
        if not isinstance(tx, dict) or set(tx) != {"body", "sig"} or not isinstance(tx["sig"], str):
            return "bad envelope"
        if len(tx["sig"]) > 20_000:
            return "signature too large"
        b = tx["body"]
        if not isinstance(b, dict) or set(b) != TX_KEYS:
            return "bad fields"
        if b["net"] != p.name:
            return "wrong network"
        if b["type"] not in TX_TYPES:
            return "unknown type"
        if not isinstance(b["from"], str) or not ADDR_RE.match(b["from"]):
            return "bad from"
        if not all(_is_uint(b[k]) for k in ("amount", "fee", "idx", "time")):
            return "bad numbers"
        ps = b["parents"]
        if (not isinstance(ps, list) or not 1 <= len(ps) <= 2 or len(set(ps)) != len(ps)
                or not all(isinstance(x, str) and HEX64_RE.match(x) for x in ps)):
            return "bad parents"
        d, t = b["data"], b["type"]
        if not isinstance(d, dict):
            return "bad data"
        if t == "transfer":
            if not (isinstance(b["to"], str) and ADDR_RE.match(b["to"]) and b["amount"] > 0 and d == {}):
                return "bad transfer"
        elif t == "register_plot":
            if b["to"] != "" or b["amount"] != 0 or set(d) != {"plot_id", "owner", "nonce", "n", "pow"}:
                return "bad registration"
            if not (isinstance(d["owner"], str) and ADDR_RE.match(d["owner"])
                    and _is_uint(d["nonce"]) and _is_uint(d["pow"])
                    and type(d["n"]) is int and 1 <= d["n"] < 2 ** 32):
                return "bad registration data"
            if d["plot_id"] != plot_id_for(d["owner"], b["from"], d["nonce"]):
                return "plot id does not match owner/key/nonce"
        elif t == "htlc_lock":
            if not (isinstance(b["to"], str) and ADDR_RE.match(b["to"]) and b["amount"] > 0):
                return "bad htlc lock"
            if (set(d) != {"hashlock", "timeout"} or not isinstance(d["hashlock"], str)
                    or not HEX64_RE.match(d["hashlock"]) or not _is_uint(d["timeout"])):
                return "bad htlc lock data"
        elif t == "htlc_claim":
            if b["to"] != "" or b["amount"] != 0 or set(d) != {"contract", "preimage"}:
                return "bad htlc claim"
            if not (isinstance(d["contract"], str) and HEX64_RE.match(d["contract"])
                    and isinstance(d["preimage"], str) and HEX64_RE.match(d["preimage"])):
                return "bad htlc claim data (preimage must be 32 bytes hex)"
        elif t == "htlc_refund":
            if (b["to"] != "" or b["amount"] != 0 or set(d) != {"contract"}
                    or not isinstance(d["contract"], str) or not HEX64_RE.match(d["contract"])):
                return "bad htlc refund"
    except Exception as e:  # noqa: BLE001
        return f"malformed: {e}"
    return None


def check_cp_form(p, cp):
    try:
        if not isinstance(cp, dict) or set(cp) != {"body", "sig"} or not isinstance(cp["sig"], str):
            return "bad envelope"
        b = cp["body"]
        if not isinstance(b, dict) or set(b) != CP_KEYS or b["net"] != p.name:
            return "bad fields or network"
        if not (_is_uint(b["height"]) and b["height"] >= 1 and _is_uint(b["time"]) and _is_uint(b["idx"])):
            return "bad numbers"
        for k in ("prev", "challenge"):
            if not isinstance(b[k], str) or not HEX64_RE.match(b[k]):
                return f"bad {k}"
        if not isinstance(b["producer"], str) or not ADDR_RE.match(b["producer"]):
            return "bad producer"
        pr = b["proof"]
        if (not isinstance(pr, dict) or set(pr) != {"plot_id", "index", "leaf"}
                or not isinstance(pr["plot_id"], str) or not HEX64_RE.match(pr["plot_id"])
                or not isinstance(pr["leaf"], str) or not HEX64_RE.match(pr["leaf"])
                or not _is_uint(pr["index"], 2 ** 32)):
            return "bad proof"
        ts = b["tips"]
        if (not isinstance(ts, list) or not 1 <= len(ts) <= MAX_TIPS or len(set(ts)) != len(ts)
                or not all(isinstance(x, str) and HEX64_RE.match(x) for x in ts)):
            return "bad tips"
    except Exception as e:  # noqa: BLE001
        return f"malformed: {e}"
    return None


class Invalid(Exception):
    pass


class MissingTx(Exception):
    def __init__(self, ids):
        super().__init__(f"{len(ids)} missing transactions")
        self.ids = ids


class State:
    """Ledger state after a checkpoint."""
    __slots__ = ("height", "time", "hash", "challenge", "leaf", "dist", "weight",
                 "balances", "last_idx", "plots", "htlcs", "processed", "receipts", "minted")

    def copy(self):
        s = State()
        for k in ("height", "time", "hash", "challenge", "leaf", "dist", "weight", "minted"):
            setattr(s, k, getattr(self, k))
        s.balances = dict(self.balances)
        s.last_idx = dict(self.last_idx)
        s.plots = dict(self.plots)
        s.htlcs = dict(self.htlcs)
        s.processed = dict(self.processed)
        s.receipts = dict(self.receipts)
        return s

    def spendable(self, p, addr, h):
        return self.balances.get(addr, 0) - p.locked(addr, h)


def genesis_checkpoint(p):
    body = {"net": p.name, "height": 0, "prev": GENESIS_REF, "time": p.genesis_time,
            "challenge": H(b"GENESIS", p.name.encode()).hex(),
            "alloc": [[p.founder, FOUNDER_ALLOCATION]] if p.founder else [],
            "founder_vesting_checkpoints": p.vesting}
    return {"body": body, "sig": ""}


def genesis_state(p, g):
    s = State()
    b = g["body"]
    s.height, s.time, s.hash = 0, b["time"], cp_hash(g)
    s.challenge, s.leaf, s.dist, s.weight, s.minted = b["challenge"], "", None, 0, 0
    s.balances = {a: amt for a, amt in b["alloc"]}
    s.last_idx, s.plots, s.htlcs, s.processed, s.receipts = {}, {}, {}, {}, {}
    return s


def apply_tx(p, st, tx, tid, h, fees):
    """Apply one ordered transaction. Invalid ones are skipped (return False)."""
    b = tx["body"]
    t, frm, idx, fee = b["type"], b["from"], b["idx"], b["fee"]
    if idx <= st.last_idx.get(frm, -1):
        return False
    bal = st.balances.get(frm, 0)
    spendable = bal - p.locked(frm, h)
    if t == "transfer":
        amt, to = b["amount"], b["to"]
        if fee < MIN_FEE or spendable < amt + fee:
            return False
        st.balances[frm] = bal - amt - fee
        st.balances[to] = st.balances.get(to, 0) + amt
    elif t == "register_plot":
        d = b["data"]
        if d["plot_id"] in st.plots:
            return False
        if fee == 0:
            if leading_zero_bits(tid) < p.pow_bits:
                return False
        else:
            if fee < MIN_FEE or spendable < fee:
                return False
            st.balances[frm] = bal - fee
        st.plots[d["plot_id"]] = {"owner": d["owner"], "key": frm, "n": d["n"], "reg": h}
    elif t == "htlc_lock":
        amt, d = b["amount"], b["data"]
        if fee < MIN_FEE or spendable < amt + fee or d["timeout"] <= h:
            return False
        st.balances[frm] = bal - amt - fee
        st.htlcs[tid] = {"from": frm, "to": b["to"], "amount": amt, "hashlock": d["hashlock"],
                         "timeout": d["timeout"], "state": "open", "preimage": None, "height": h}
    elif t in ("htlc_claim", "htlc_refund"):
        d = b["data"]
        c = st.htlcs.get(d["contract"])
        if not c or c["state"] != "open" or fee < MIN_FEE or fee >= c["amount"]:
            return False
        c = dict(c)
        if t == "htlc_claim":
            if frm != c["to"] or h > c["timeout"]:
                return False
            if hashlib.sha256(bytes.fromhex(d["preimage"])).hexdigest() != c["hashlock"]:
                return False
            c["state"], c["preimage"] = "claimed", d["preimage"]
        else:
            if frm != c["from"] or h <= c["timeout"]:
                return False
            c["state"] = "refunded"
        st.htlcs[d["contract"]] = c
        st.balances[frm] = bal + c["amount"] - fee
    else:
        return False
    st.last_idx[frm] = idx
    fees[0] += fee
    return True


def order_txs(st, tips, txs, cp_time):
    """Deterministic total order of the DAG transactions a checkpoint confirms."""
    seen, missing, stack = set(), [], list(tips)
    while stack:
        t = stack.pop()
        if t == GENESIS_REF or t in seen or t in st.processed:
            continue
        tx = txs.get(t)
        if tx is None:
            if t not in missing:
                missing.append(t)
            continue
        bt = tx["body"]["time"]
        if bt < cp_time - TX_MAX_AGE:
            continue                       # expired: never confirmed
        if bt > cp_time + MAX_DRIFT:
            raise Invalid("checkpoint confirms a transaction from the future")
        seen.add(t)
        if len(seen) > MAX_TXS_PER_CHECKPOINT:
            raise Invalid("too many transactions in one checkpoint")
        stack.extend(tx["body"]["parents"])
    if missing:
        raise MissingTx(missing)
    indeg, kids = {t: 0 for t in seen}, {t: [] for t in seen}
    for t in seen:
        for par in txs[t]["body"]["parents"]:
            if par in seen:
                indeg[t] += 1
                kids[par].append(t)
    heap = [(txs[t]["body"]["time"], t) for t in seen if indeg[t] == 0]
    heapq.heapify(heap)
    out = []
    while heap:
        _, t = heapq.heappop(heap)
        out.append(t)
        for k in kids[t]:
            indeg[k] -= 1
            if indeg[k] == 0:
                heapq.heappush(heap, (txs[k]["body"]["time"], k))
    return out


def apply_checkpoint(p, parent, cp, txs, now=None):
    b = cp["body"]
    h = b["height"]
    if b["prev"] != parent.hash or h != parent.height + 1:
        raise Invalid("does not extend its parent")
    if b["time"] < parent.time + p.interval:
        raise Invalid("too early")
    if now is not None and b["time"] > now + MAX_DRIFT:
        raise Invalid("timestamp in the future")
    if b["challenge"] != next_challenge(parent):
        raise Invalid("wrong challenge")
    pr = b["proof"]
    chash = cp_hash(cp)
    if verify_sig(b["producer"], bytes.fromhex(chash), cp["sig"]) != b["idx"]:
        raise Invalid("bad producer signature")
    order = order_txs(parent, b["tips"], txs, b["time"])

    st = parent.copy()
    fees = [0]
    for t in order:
        applied = apply_tx(p, st, txs[t], t, h, fees)
        st.processed[t] = txs[t]["body"]["time"]
        st.receipts[t] = {"applied": applied, "checkpoint_hash": chash, "height": h}

    # Normal rule: the plot must have been registered REG_DELAY checkpoints ago.
    # Bootstrap rule: while no plot on chain is old enough (network launch),
    # any registered plot - including one registered by this very checkpoint -
    # may produce, so the chain can start.
    plot = st.plots.get(pr["plot_id"])
    if not plot:
        raise Invalid("plot not registered")
    if plot["reg"] > h - REG_DELAY:
        if any(v["reg"] <= h - REG_DELAY for v in parent.plots.values()):
            raise Invalid("plot registered too recently")
    if plot["key"] != b["producer"]:
        raise Invalid("producer does not control this plot")
    if pr["index"] >= plot["n"]:
        raise Invalid("proof index outside plot")
    if plot_leaf(bytes.fromhex(pr["plot_id"]), pr["index"]).hex() != pr["leaf"]:
        raise Invalid("storage proof does not verify")
    if b["idx"] <= st.last_idx.get(b["producer"], -1):
        raise Invalid("producer signature index reused")
    dist = (int(pr["leaf"], 16) - int(b["challenge"], 16)) % (1 << 256)
    st.last_idx[b["producer"]] = b["idx"]
    reward = min(p.reward(h), MINING_SUPPLY - st.minted)
    st.minted += reward
    st.balances[plot["owner"]] = st.balances.get(plot["owner"], 0) + reward + fees[0]
    cutoff = b["time"] - 2 * TX_MAX_AGE
    st.processed = {k: v for k, v in st.processed.items() if v >= cutoff}
    # Cross-chain escrows can remain open for days. Keep their applied receipts
    # on the canonical branch so a verifier can still prove the exact lock,
    # claim/refund fee and checkpoint after ordinary mempool history expires.
    # Each fork owns its own receipts, so reorganizations keep the same anchors.
    st.receipts = {
        k: v for k, v in st.receipts.items()
        if k in st.processed or (v["applied"] and
            txs.get(k, {}).get("body", {}).get("type") in
            ("htlc_lock", "htlc_claim", "htlc_refund"))
    }
    st.height, st.time, st.hash = h, b["time"], chash
    st.challenge, st.leaf, st.dist = b["challenge"], pr["leaf"], dist
    st.weight = parent.weight + (1 << 256) // (dist + 1)
    return st


# =============================================================================
# 6. NODE (ledger, mempool, fork choice, persistence, checkpoint production)
# =============================================================================
class Node:
    def __init__(self, p, datadir=None, log=print):
        self.p, self.log = p, log
        self.lock = threading.RLock()
        self.txs, self.tips = {}, set()
        self.cps, self.states, self.children = {}, {}, {}
        self._produced = set()
        g = genesis_checkpoint(p)
        gs = genesis_state(p, g)
        self.genesis_hash = gs.hash
        self.cps[gs.hash], self.states[gs.hash] = g, gs
        self.best, self.main = gs.hash, [gs.hash]
        self.db = None
        if datadir:
            os.makedirs(datadir, exist_ok=True)
            self.db = sqlite3.connect(os.path.join(datadir, f"{p.name}.db"),
                                      check_same_thread=False, isolation_level=None)
            self.db.execute("PRAGMA synchronous=FULL")
            if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise RuntimeError("ledger database integrity check failed")
            self.db.execute("CREATE TABLE IF NOT EXISTS txs (id TEXT PRIMARY KEY, j TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS cps (hash TEXT PRIMARY KEY, j TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            row = self.db.execute("SELECT value FROM metadata WHERE key='genesis'").fetchone()
            if row and row[0] != self.genesis_hash:
                raise RuntimeError("stored genesis differs from configured genesis")
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('genesis', ?)", (self.genesis_hash,))
            self._load()

    def _load(self):
        n_tx = n_cp = 0
        for ident, j in self.db.execute("SELECT id, j FROM txs ORDER BY rowid"):
            obj = json.loads(j)
            if tx_id(obj) != ident or self.add_tx(obj, relaxed=True, persist=False)[0] != "ok":
                raise RuntimeError("stored transaction failed validation; recover from a verified backup")
            n_tx += 1
        for ident, j in self.db.execute("SELECT hash, j FROM cps ORDER BY rowid"):
            obj = json.loads(j)
            if cp_hash(obj) != ident or self.add_checkpoint(obj, relaxed=True, persist=False)[0] != "ok":
                raise RuntimeError("stored checkpoint failed validation; recover from a verified backup")
            n_cp += 1
        if n_tx or n_cp:
            self.log(f"loaded {n_tx} transactions, {n_cp} checkpoints; height {self.height()}")

    def best_state(self):
        return self.states[self.best]

    def height(self):
        return self.best_state().height

    # ---- transactions --------------------------------------------------
    def add_tx(self, tx, relaxed=False, persist=True):
        with self.lock:
            err = check_tx_form(self.p, tx)
            if err:
                return "invalid", err
            tid = tx_id(tx)
            if tid in self.txs:
                return "dup", tid
            b = tx["body"]
            missing = [x for x in b["parents"] if x != GENESIS_REF and x not in self.txs]
            if missing:
                return "missing", missing
            st = self.best_state()
            if not relaxed:
                now = time.time()
                if b["time"] > now + MAX_DRIFT or b["time"] < now - TX_MAX_AGE:
                    return "invalid", "stale or future timestamp"
                if b["idx"] <= st.last_idx.get(b["from"], -1):
                    return "invalid", "signature index already used"
            if verify_sig(b["from"], bytes.fromhex(tid), tx["sig"]) != b["idx"]:
                return "invalid", "bad signature"
            if not relaxed:
                h = st.height + 1
                t = b["type"]
                if t in ("transfer", "htlc_lock"):
                    if b["fee"] < MIN_FEE:
                        return "invalid", f"fee below minimum ({MIN_FEE} units)"
                    if st.spendable(self.p, b["from"], h) < b["amount"] + b["fee"]:
                        return "invalid", "insufficient spendable balance"
                if t == "register_plot" and b["fee"] == 0 and leading_zero_bits(tid) < self.p.pow_bits:
                    return "invalid", "registration work too low"
            if persist and self.db:
                self.db.execute("INSERT INTO txs VALUES (?,?)", (tid, json.dumps(tx)))
            self.txs[tid] = tx
            self.tips.add(tid)
            self.tips.difference_update(b["parents"])
            return "ok", tid

    def tx_parents(self):
        with self.lock:
            st, now = self.best_state(), time.time()
            cands = sorted((self.txs[t]["body"]["time"], t) for t in self.tips
                           if t not in st.processed
                           and self.txs[t]["body"]["time"] > now - TX_MAX_AGE / 2)
            ps = [t for _, t in cands[-2:]]
            return ps or [GENESIS_REF]

    # ---- checkpoints -----------------------------------------------------
    def add_checkpoint(self, cp, relaxed=False, persist=True):
        with self.lock:
            err = check_cp_form(self.p, cp)
            if err:
                return "invalid", err
            h = cp_hash(cp)
            if h in self.cps:
                return "dup", h
            b = cp["body"]
            parent = self.states.get(b["prev"])
            if parent is None:
                if b["prev"] in self.cps:
                    return "invalid", "parent is beyond the reorg limit"
                return "missing_parent", b["prev"]
            if b["height"] <= self.height() - REORG_LIMIT:
                return "invalid", "beyond the reorg limit"
            try:
                st = apply_checkpoint(self.p, parent, cp, self.txs,
                                      None if relaxed else time.time())
            except MissingTx as e:
                return "missing_txs", e.ids
            except Invalid as e:
                return "invalid", str(e)
            except (KeyError, TypeError, ValueError) as e:
                return "invalid", f"malformed: {e}"
            if persist and self.db:
                self.db.execute("INSERT INTO cps VALUES (?,?)", (h, json.dumps(cp)))
            self.cps[h], self.states[h] = cp, st
            self.children.setdefault(b["prev"], []).append(h)
            cur = self.best_state()
            if st.weight > cur.weight or (st.weight == cur.weight and h < cur.hash):
                self._set_best(h)
            return "ok", h

    def _set_best(self, newhash):
        path, x = [], newhash
        while True:
            ht = self.cps[x]["body"]["height"]
            if ht < len(self.main) and self.main[ht] == x:
                break
            path.append(x)
            x = self.cps[x]["body"]["prev"]
        del self.main[ht + 1:]
        self.main.extend(reversed(path))
        self.best = newhash
        floor = self.height() - REORG_LIMIT
        for k in [k for k, s in self.states.items() if s.height < floor]:
            del self.states[k]

    def chain_from(self, start, limit=500):
        with self.lock:
            return [self.cps[h] for h in self.main[max(1, start):max(1, start) + limit]]

    # ---- production --------------------------------------------------------
    def _select_tips(self, parent, now):
        cands = sorted((self.txs[t]["body"]["time"], t) for t in self.tips
                       if t not in parent.processed
                       and now - TX_MAX_AGE + 60 < self.txs[t]["body"]["time"] <= now)
        chosen = [t for _, t in cands][:MAX_TIPS]
        while chosen:
            try:
                order_txs(parent, chosen, self.txs, now)
                return chosen
            except (Invalid, MissingTx):
                chosen = chosen[:len(chosen) // 2]
        return [GENESIS_REF]

    def build_checkpoint(self, parent, lp, now):
        idx_in_plot, leaf, _ = lp.lookup(next_challenge(parent))
        tips = self._select_tips(parent, now)
        sidx = lp.key.reserve_index(parent.last_idx.get(lp.key.address, -1))
        body = {"net": self.p.name, "height": parent.height + 1, "prev": parent.hash,
                "time": max(now, parent.time + self.p.interval),
                "challenge": next_challenge(parent),
                "proof": {"plot_id": lp.plot_id, "index": idx_in_plot, "leaf": leaf},
                "tips": tips, "producer": lp.key.address, "idx": sidx}
        cp = {"body": body, "sig": ""}
        cp["sig"] = lp.key.sign(bytes.fromhex(cp_hash(cp)), sidx)
        return cp

    def try_produce(self, plots, now=None):
        with self.lock:
            now = int(now if now is not None else time.time())
            tip = self.best_state()
            if now < tip.time + self.p.interval or tip.hash in self._produced:
                return None
            h, chal = tip.height + 1, next_challenge(tip)
            bootstrap = not any(v["reg"] <= h - REG_DELAY for v in tip.plots.values())
            pending = set()
            if bootstrap:
                pending = {tx["body"]["data"]["plot_id"] for t, tx in self.txs.items()
                           if tx["body"]["type"] == "register_plot" and t not in tip.processed}
            best = None
            for lp in plots:
                if lp.key.data["next_index"] >= lp.key.capacity:
                    continue
                reg = tip.plots.get(lp.plot_id)
                if reg:
                    if reg["key"] != lp.key.address or (reg["reg"] > h - REG_DELAY and not bootstrap):
                        continue
                elif lp.plot_id not in pending:
                    continue
                dist = lp.lookup(chal)[2]
                if best is None or dist < best[0]:
                    best = (dist, lp)
            if best is None:
                return None
            for ch in self.children.get(tip.hash, []):
                if ch in self.states and self.states[ch].dist <= best[0]:
                    return None
            try:
                cp = self.build_checkpoint(tip, best[1], now)
            except WalletExhausted:
                self.log("plot signing key exhausted; create and register a new plot "
                         f"to continue mining: {best[1].plot_id}")
                return None
            status, info = self.add_checkpoint(cp)
            if status != "ok":
                self.log(f"own checkpoint rejected: {info}")
                return None
            self._produced.add(tip.hash)
            return cp

    # ---- queries --------------------------------------------------------
    def account(self, addr):
        with self.lock:
            st = self.best_state()
            bal = st.balances.get(addr, 0)
            locked = self.p.locked(addr, st.height + 1)
            return {"address": addr, "balance": bal, "locked": locked,
                    "spendable": bal - locked, "last_idx": st.last_idx.get(addr, -1),
                    "height": st.height}

    def info(self):
        with self.lock:
            st = self.best_state()
            return {"network": self.p.name, "version": VERSION, "genesis": self.genesis_hash,
                    "height": st.height, "best": st.hash, "weight": str(st.weight),
                    "checkpoint_time": st.time,
                    "real_funds_ready": False,
                    "minted": st.minted, "founder_allocation": FOUNDER_ALLOCATION if self.p.founder else 0,
                    "plots": len(st.plots), "mempool_tips": len(self.tips)}

    def receipt(self, tid):
        """Applied/rejected result anchored to the current canonical chain.

        Ordinary receipt history is bounded like processed transactions.
        Applied HTLC receipts remain available for long-lived escrow proofs.
        Unknown never proves an applied transfer or an exchange deposit.
        """
        with self.lock:
            st = self.best_state()
            rec = st.receipts.get(tid)
            return {"txid": tid, "status": ("applied" if rec["applied"] else "rejected")
                    if rec else "unknown", "applied": rec["applied"] if rec else None,
                    "checkpoint_hash": rec["checkpoint_hash"] if rec else None,
                    "height": rec["height"] if rec else None,
                    "canonical_best": st.hash, "canonical_height": st.height}


def make_register_tx(p, lp, parents, last_idx):
    idx = lp.key.reserve_index(last_idx)
    body = {"net": p.name, "type": "register_plot", "from": lp.key.address, "to": "",
            "amount": 0, "fee": 0, "idx": idx, "parents": parents, "time": int(time.time()),
            "data": {"plot_id": lp.plot_id, "owner": lp.meta["owner"],
                     "nonce": lp.meta["nonce"], "n": lp.n, "pow": 0}}
    tx = {"body": body, "sig": ""}
    while leading_zero_bits(tx_id(tx)) < p.pow_bits:
        body["data"]["pow"] += 1
    tx["sig"] = lp.key.sign(bytes.fromhex(tx_id(tx)), idx)
    return tx


def make_tx(p, wallet, ttype, to, amount, fee, data, parents, last_idx):
    idx = wallet.reserve_index(last_idx)
    body = {"net": p.name, "type": ttype, "from": wallet.address, "to": to, "amount": amount,
            "fee": fee, "idx": idx, "parents": parents, "time": int(time.time()), "data": data}
    tx = {"body": body, "sig": ""}
    tx["sig"] = wallet.sign(bytes.fromhex(tx_id(tx)), idx)
    return tx


# =============================================================================
# 7. PEER-TO-PEER NETWORK (HTTP/JSON gossip)
# =============================================================================
MAX_PEER_RESPONSE = 16_000_000
MAX_PEERS = 64
MAX_SYNC_PAGES = 100


def peer_url(peer, discovered=False):
    """Discovery cannot turn a remote peer into a local-network HTTP proxy.

    Operators may explicitly configure private peers. Automatically learned
    peers must be public literal IPs (no DNS rebinding) or the pinned seed.
    """
    if not isinstance(peer, str) or len(peer) > 255 or any(c.isspace() for c in peer):
        raise ValueError("invalid peer URL")
    url = peer if "://" in peer else "http://" + peer
    parsed = urlparse(url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or parsed.port == 0):
        raise ValueError("invalid peer URL")
    url = url.rstrip("/")
    if discovered and url != DEFAULT_MAINNET_NODE:
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            raise ValueError("discovered peers must use a public IP; configure DNS peers explicitly")
        if not address.is_global:
            raise ValueError("discovered peers must use a public IP")
    return url


class _NoPeerRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("peer redirects are disabled")


def read_peer_json(response, limit=MAX_PEER_RESPONSE):
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("peer response exceeds size limit")
    value = json.loads(raw or b"{}")
    if not isinstance(value, dict):
        raise ValueError("peer response must be an object")
    return value


def http_json(base, path, obj=None, timeout=15):
    url = peer_url(base) + path
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": f"Aurion/{VERSION}"})
    with urllib.request.build_opener(_NoPeerRedirect).open(req, timeout=timeout) as r:
        return read_peer_json(r)


class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class P2P:
    def __init__(self, node, port, peers, public=None, bind="0.0.0.0"):
        self.node, self.port, self.bind = node, port, bind
        if len(peers) > MAX_PEERS:
            raise ValueError("at most 64 configured peers are supported")
        self.peers = set(peers)
        for peer in self.peers:
            peer_url(peer)
        self.self_addr = public or f"127.0.0.1:{port}"
        self.log = node.log
        self._gossip_lock = threading.Lock()
        self._checkpoint_locks = {}
        self._sync_lock = threading.Lock()
        self._outbound_slots = threading.BoundedSemaphore(8)

    def _spawn(self, target, args=()):
        if not self._outbound_slots.acquire(blocking=False):
            return False
        def work():
            try:
                target(*args)
            finally:
                self._outbound_slots.release()
        threading.Thread(target=work, daemon=True).start()
        return True

    def add_peer(self, peer):
        try:
            normalized = peer_url(peer, discovered=True)
        except (ValueError, TypeError):
            return False
        with self._gossip_lock:
            if normalized == peer_url(self.self_addr) or len(self.peers) >= MAX_PEERS:
                return False
            self.peers.add(normalized)
        return True

    def broadcast(self, path, obj):
        for peer in list(self.peers):
            target = self._post_checkpoint if path == "/checkpoint" else self._post_quiet
            args = (peer, obj) if path == "/checkpoint" else (peer, path, obj)
            self._spawn(target, args)

    def _post_quiet(self, peer, path, obj):
        try:
            http_json(peer, path, obj, timeout=10)
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _post_reply(peer, path, obj):
        """Dependency failures use HTTP 400 but still carry protocol JSON."""
        try:
            return http_json(peer, path, obj, timeout=10)
        except urllib.error.HTTPError as e:
            return read_peer_json(e)

    def _post_checkpoint(self, peer, cp):
        """Send transactions before the checkpoint and repair missing dependencies.

        This changes transport ordering only. A recipient still validates every
        envelope with the original ledger rules. Work and retries are bounded.
        """
        with self._gossip_lock:
            peer_lock = self._checkpoint_locks.setdefault(peer, threading.Lock())
        with peer_lock:
            with self.node.lock:
                parent = self.node.states.get(cp["body"]["prev"])
                ids = order_txs(parent, cp["body"]["tips"], self.node.txs,
                                cp["body"]["time"]) if parent else []
                jobs = [("/tx", self.node.txs[tid]) for tid in ids]
            jobs.append(("/checkpoint", cp))
            pending, attempts = list(reversed(jobs)), {}
            for _ in range(4 * MAX_TXS_PER_CHECKPOINT):
                if not pending:
                    return True
                path, obj = pending.pop()
                ident = tx_id(obj) if path == "/tx" else cp_hash(obj)
                key = (path, ident)
                attempts[key] = attempts.get(key, 0) + 1
                if attempts[key] > 3:
                    self.log(f"checkpoint delivery to {peer} stopped after repeated failures")
                    return False
                try:
                    reply = self._post_reply(peer, path, obj)
                except (OSError, ValueError) as e:
                    self.log(f"checkpoint delivery to {peer} failed; retrying: {e}")
                    pending.append((path, obj))
                    continue
                status = reply.get("status") if isinstance(reply, dict) else None
                if status in ("ok", "dup"):
                    attempts.pop(key, None)
                    continue
                missing = reply.get("info") if isinstance(reply, dict) else None
                dependencies = []
                with self.node.lock:
                    if status in ("missing", "missing_txs") and isinstance(missing, list):
                        if (len(missing) > MAX_TXS_PER_CHECKPOINT
                                or not all(isinstance(tid, str) and HEX64_RE.fullmatch(tid)
                                           for tid in missing)):
                            return False
                        for tid in dict.fromkeys(missing):
                            tx = self.node.txs.get(tid) if isinstance(tid, str) else None
                            if tx is None:
                                self.log(f"cannot deliver checkpoint to {peer}: transaction unavailable")
                                return False
                            dependencies.append(("/tx", tx))
                    elif status == "missing_parent" and missing == obj["body"].get("prev"):
                        previous = self.node.cps.get(missing)
                        if previous is not None and previous["body"]["height"] > 0:
                            dependencies.append(("/checkpoint", previous))
                if not dependencies:
                    self.log(f"checkpoint delivery to {peer} rejected: {status}: {missing}")
                    return False
                pending.append((path, obj))
                pending.extend(reversed(dependencies))
            self.log(f"checkpoint delivery to {peer} exceeded its dependency limit")
            return False

    def fetch_txs(self, peer, ids):
        need, pending, rounds, requested = list(ids)[:MAX_TXS_PER_CHECKPOINT], {}, 0, set()
        while need and rounds < 50 and len(requested) < MAX_TXS_PER_CHECKPOINT:
            rounds += 1
            batch, need = need[:200], need[200:]
            batch = [i for i in batch if i not in requested][:MAX_TXS_PER_CHECKPOINT - len(requested)]
            if not batch:
                continue
            requested.update(batch)
            try:
                res = http_json(peer, "/txs", {"ids": batch})
            except Exception:  # noqa: BLE001
                return
            returned = res.get("txs", [])
            if not isinstance(returned, list) or len(returned) > len(batch):
                return
            for tx in returned:
                try:
                    tid = tx_id(tx)
                    if tid in batch:
                        pending[tid] = tx
                except Exception:  # noqa: BLE001
                    continue
            progress = True
            while progress:
                progress = False
                for tid, tx in list(pending.items()):
                    st, info = self.node.add_tx(tx, relaxed=True)
                    if st == "missing":
                        for m in info:
                            if m not in requested and m not in pending and m not in need:
                                need.append(m)
                    else:
                        del pending[tid]
                        progress = progress or st == "ok"

    def handle_checkpoint(self, cp, peers=None):
        st, info = self.node.add_checkpoint(cp)
        if st == "missing_txs":
            for peer in (peers or list(self.peers)):
                self.fetch_txs(peer, info)
                st, info = self.node.add_checkpoint(cp)
                if st != "missing_txs":
                    break
        elif st == "missing_parent":
            self._spawn(self.sync_once)
        return st, info

    def sync_once(self):
        if not self._sync_lock.acquire(blocking=False):
            return
        try:
            self._sync_peers()
        finally:
            self._sync_lock.release()

    def _sync_peers(self):
        for peer in list(self.peers):
            try:
                info = http_json(peer, "/info")
                if info.get("genesis") != self.node.genesis_hash:
                    continue
                # A seed can accept web-wallet transfers without advancing its
                # chain. Miners must fetch the mempool even at equal chain weight.
                tips = http_json(peer, "/tips").get("parents", [])
                if isinstance(tips, list):
                    ids = [tid for tid in tips[:MAX_TIPS] if isinstance(tid, str)
                           and HEX64_RE.fullmatch(tid) and tid != GENESIS_REF]
                    if ids:
                        self.fetch_txs(peer, ids)
                extras = http_json(peer, "/peers").get("peers", [])
                if isinstance(extras, list):
                    for extra in extras[:50]:
                        self.add_peer(extra)
                peer_weight = int(info["weight"])
                if peer_weight < self.node.best_state().weight or info.get("best") == self.node.best:
                    if peer_weight < self.node.best_state().weight:
                        # Retry a latest checkpoint after a previous delivery or
                        # connectivity failure; missing ancestors are repaired.
                        with self.node.lock:
                            latest = self.node.cps[self.node.best]
                        self._post_checkpoint(peer, latest)
                    continue
                start = max(1, self.node.height() - REORG_LIMIT + 1)
                for _ in range(MAX_SYNC_PAGES):
                    cps = http_json(peer, f"/chain?from={start}").get("checkpoints", [])
                    if not isinstance(cps, list) or len(cps) > 500:
                        raise ValueError("invalid checkpoint page")
                    for cp in cps:
                        if cp.get("body", {}).get("height") != start:
                            raise ValueError("peer returned non-contiguous checkpoints")
                        st, msg = self.handle_checkpoint(cp, [peer])
                        if st not in ("ok", "dup"):
                            raise RuntimeError(f"peer {peer} sent bad checkpoint: {msg}")
                        start += 1
                    if len(cps) < 500:
                        break
                self.log(f"synced from {peer}: height {self.node.height()}")
            except Exception as e:  # noqa: BLE001
                self.log(f"sync with {peer} failed: {e}")

    def make_handler(self):
        p2p, node = self, self.node

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(10)

            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("transfer encoding is unsupported")
                n = int(self.headers.get("Content-Length", 0))
                if not 0 <= n <= 4_000_000:
                    raise ValueError("Content-Length must be between 0 and 4000000")
                body = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("JSON object required")
                return body

            def do_GET(self):
                try:
                    u = urlparse(self.path)
                    parts = [x for x in u.path.split("/") if x]
                    q = parse_qs(u.query)
                    if u.path == "/info":
                        return self._send(200, node.info())
                    if u.path == "/peers":
                        return self._send(200, {"peers": sorted(p2p.peers)})
                    if u.path == "/tips":
                        return self._send(200, {"parents": node.tx_parents()})
                    if u.path == "/chain":
                        return self._send(200, {"checkpoints": node.chain_from(int(q.get("from", ["1"])[0]))})
                    if u.path == "/founder":
                        a = node.p.founder
                        return self._send(200, {"address": a, "allocation": FOUNDER_ALLOCATION if a else 0,
                                                "vesting_checkpoints": node.p.vesting,
                                                **(node.account(a) if a else {})})
                    if len(parts) == 2 and parts[0] == "account":
                        return self._send(200, node.account(parts[1]))
                    if len(parts) == 2 and parts[0] == "tx":
                        tx = node.txs.get(parts[1])
                        return self._send(200 if tx else 404, {"tx": tx})
                    if len(parts) == 2 and parts[0] == "receipt":
                        if not HEX64_RE.fullmatch(parts[1]):
                            return self._send(400, {"error": "transaction id must be 64 hex characters"})
                        return self._send(200, node.receipt(parts[1]))
                    if len(parts) == 2 and parts[0] == "htlc":
                        with node.lock:
                            c = node.best_state().htlcs.get(parts[1])
                        return self._send(200 if c else 404, {"htlc": c})
                    return self._send(404, {"error": "not found"})
                except Exception as e:  # noqa: BLE001
                    return self._send(400, {"error": str(e)})

            def do_POST(self):
                try:
                    body = self._body()
                    if self.path == "/tx":
                        st, info = node.add_tx(body)
                        if st == "missing":
                            for peer in list(p2p.peers):
                                p2p.fetch_txs(peer, info)
                            st, info = node.add_tx(body)
                        if st == "ok":
                            p2p.broadcast("/tx", body)
                        return self._send(200 if st in ("ok", "dup") else 400, {"status": st, "info": info})
                    if self.path == "/txs":
                        ids = body.get("ids", [])
                        if not isinstance(ids, list) or len(ids) > 200 or not all(
                                isinstance(i, str) and HEX64_RE.fullmatch(i) for i in ids):
                            raise ValueError("ids must contain at most 200 transaction hashes")
                        with node.lock:
                            txs = [node.txs[i] for i in ids if i in node.txs]
                        return self._send(200, {"txs": txs})
                    if self.path == "/checkpoint":
                        st, info = p2p.handle_checkpoint(body)
                        if st == "ok":
                            p2p.broadcast("/checkpoint", body)
                        return self._send(200 if st in ("ok", "dup") else 400, {"status": st, "info": info})
                    if self.path == "/peers":
                        addr = body.get("addr", "")
                        p2p.add_peer(addr)
                        return self._send(200, {"peers": sorted(p2p.peers)})
                    return self._send(404, {"error": "not found"})
                except Exception as e:  # noqa: BLE001
                    return self._send(400, {"error": str(e)})

        return Handler

    def start(self):
        srv = BoundedHTTPServer((self.bind, self.port), self.make_handler())
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        for peer in list(self.peers):
            self._post_quiet(peer, "/peers", {"addr": self.self_addr})
        return srv


def bootstrap_peers(args, p):
    if args.peer is not None:
        return list(args.peer)
    return [DEFAULT_MAINNET_NODE] if p.name == "aurion-mainnet" else []


def run_node(p, args):
    node = Node(p, args.datadir)
    log = node.log
    log(f"Aurion {VERSION} on {p.name}  genesis {node.genesis_hash[:16]}...  height {node.height()}")
    if p.founder:
        log(f"founder allocation: {fmt(FOUNDER_ALLOCATION)} to {p.founder[:20]}... "
            + (f"(vests over {p.vesting:,} checkpoints)" if p.vesting else "(available from genesis)"))
    p2p = P2P(node, args.port or p.port, bootstrap_peers(args, p), args.public, args.bind)
    p2p.start()
    log(f"listening on {args.bind}:{p2p.port}; peers: {', '.join(sorted(p2p.peers)) or 'none'}")
    plots = load_plots(args.plots) if args.mine else []
    if args.mine:
        total = sum(lp.n for lp in plots) * 36 / 2 ** 20
        log(f"mining with {len(plots)} plot(s), {total:,.0f} MB" if plots
            else f"no plots in {args.plots}: create one with `plot create`")
    submitted, last_sync = {}, 0
    try:
        while True:
            if time.time() - last_sync > 15:
                p2p.sync_once()
                last_sync = time.time()
            for lp in list(plots):
                st = node.best_state()
                if lp.plot_id not in st.plots and time.time() - submitted.get(lp.plot_id, 0) > 300:
                    log(f"registering plot {lp.plot_id[:16]}... (doing anti-spam work)")
                    try:
                        tx = make_register_tx(p, lp, node.tx_parents(), st.last_idx.get(lp.key.address, -1))
                    except WalletExhausted:
                        log(f"plot signing key exhausted; create a new plot: {lp.plot_id}")
                        plots.remove(lp)
                        continue
                    status, info = node.add_tx(tx)
                    if status == "ok":
                        p2p.broadcast("/tx", tx)
                    submitted[lp.plot_id] = time.time()
            cp = node.try_produce(plots) if plots else None
            if cp:
                p2p.broadcast("/checkpoint", cp)
                log(f"produced checkpoint {cp['body']['height']}  reward {fmt(p.reward(cp['body']['height']))}")
            time.sleep(1)
    except KeyboardInterrupt:
        log("stopping")


# =============================================================================
# 8. BITCOIN SIDE OF ATOMIC SWAPS (bech32 + P2WSH HTLC script)
# =============================================================================
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frm, to, pad=True):
    acc = bits = 0
    out, maxv = [], (1 << to) - 1
    for v in data:
        if v < 0 or v >> frm:
            return None
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (to - bits)) & maxv)
    elif not pad and (bits >= frm or ((acc << (to - bits)) & maxv)):
        return None
    return out


def segwit_encode(hrp, ver, prog):
    data = [ver] + _convertbits(prog, 8, 5)
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 1
    return hrp + "1" + "".join(_B32[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def segwit_decode(hrp, addr):
    addr = addr.lower()
    pos = addr.rfind("1")
    if addr[:pos] != hrp or len(addr) - pos < 8:
        raise ValueError(f"not a {hrp} bech32 address")
    data = [_B32.find(c) for c in addr[pos + 1:]]
    if -1 in data or _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("bad bech32 checksum")
    prog = _convertbits(data[1:-6], 5, 8, False)
    if prog is None or data[0] != 0:
        raise ValueError("only segwit v0 addresses supported")
    return data[0], bytes(prog)


def _push(b):
    assert len(b) < 76
    return bytes([len(b)]) + b


def _scriptnum(n):
    r = bytearray()
    while n:
        r.append(n & 0xff)
        n >>= 8
    if r and r[-1] & 0x80:
        r.append(0)
    return bytes(r)


def btc_htlc(hashlock_hex, recipient_addr, refund_addr, locktime, hrp):
    _, rpkh = segwit_decode(hrp, recipient_addr)
    _, fpkh = segwit_decode(hrp, refund_addr)
    if len(rpkh) != 20 or len(fpkh) != 20:
        raise ValueError("use native segwit P2WPKH addresses (bc1q... with 42 characters)")
    s = (bytes([0x63, 0x82]) + _push(b"\x20") + bytes([0x88, 0xa8]) + _push(bytes.fromhex(hashlock_hex))
         + bytes([0x88, 0x76, 0xa9]) + _push(rpkh)
         + bytes([0x67]) + _push(_scriptnum(locktime)) + bytes([0xb1, 0x75, 0x76, 0xa9]) + _push(fpkh)
         + bytes([0x68, 0x88, 0xac]))
    return s, segwit_encode(hrp, 0, hashlib.sha256(s).digest())


# =============================================================================
# 9. COMMAND LINE
# =============================================================================
def node_url(args, p):
    return args.node or (DEFAULT_MAINNET_NODE if p.name == "aurion-mainnet"
                         else f"http://127.0.0.1:{p.port}")


def cli_send_tx(args, p, wallet, ttype, to, amount, fee, data):
    base = node_url(args, p)
    acct = http_json(base, f"/account/{wallet.address}")
    parents = http_json(base, "/tips")["parents"]
    tx = make_tx(p, wallet, ttype, to, amount, fee, data, parents, acct["last_idx"])
    try:
        res = http_json(base, "/tx", tx)
    except urllib.error.HTTPError as e:
        res = json.loads(e.read() or b"{}")
    print(json.dumps(res, indent=1))
    return tx_id(tx), res


def main(argv=None):
    ap = argparse.ArgumentParser(description="Aurion (AUR) node, wallet, miner and swap tool")
    ap.add_argument("--network", default="testnet", choices=["mainnet", "testnet", "regtest"])
    ap.add_argument("--allow-unaudited-mainnet", action="store_true",
                    help="explicitly acknowledge known flaws and opt into experimental mainnet")
    ap.add_argument("--founder", help="testnet/regtest only: founder address for a private test network")
    ap.add_argument("--node", help="node URL for clients (default mainnet public seed; other networks local)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("wallet", help="create or inspect a wallet")
    w.add_argument("action", choices=["new", "info"])
    w.add_argument("--file", default="aurion-wallet.json")
    w.add_argument("--encrypt", action="store_true", help="protect the wallet with a password")

    pl = sub.add_parser("plot", help="create storage plots for mining")
    pl.add_argument("action", choices=["create", "list"])
    pl.add_argument("--dir", default="plots")
    pl.add_argument("--size-mb", type=cli_plot_size, default=100)
    pl.add_argument("--reward-address")

    nd = sub.add_parser("node", help="run a full node")
    nd.add_argument("--datadir", default="aurion-data")
    nd.add_argument("--port", type=int)
    nd.add_argument("--bind", default="127.0.0.1")
    nd.add_argument("--public", help="host:port other peers should use to reach you")
    nd.add_argument("--peer", action="append", help="host:port of a peer (repeatable)")
    nd.add_argument("--mine", action="store_true")
    nd.add_argument("--plots", default="plots")

    b = sub.add_parser("balance", help="show an address balance")
    b.add_argument("address")

    s = sub.add_parser("send", help="send AUR")
    s.add_argument("to")
    s.add_argument("amount", type=cli_amount)
    s.add_argument("--fee", type=cli_amount, default="0.00001")
    s.add_argument("--file", default="aurion-wallet.json")

    sub.add_parser("info", help="node status")
    sub.add_parser("genesis", help="print the genesis checkpoint and its hash")
    sub.add_parser("founder", help="show the founder allocation and vesting status")
    sub.add_parser("selftest", help="run the built-in test suite")

    sw = sub.add_parser("swap", help="experimental test-only HTLC tools", description=SWAP_HELP,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    ss = sw.add_subparsers(dest="swap_cmd", required=True)
    ss.add_parser("secret", help="generate a secret and its hashlock")
    lk = ss.add_parser("lock", help="lock AUR in an HTLC")
    lk.add_argument("--to", required=True)
    lk.add_argument("--amount", type=cli_amount, required=True)
    lk.add_argument("--hash", required=True)
    lk.add_argument("--timeout", type=int, default=2880, help="checkpoints until refundable")
    lk.add_argument("--file", default="aurion-wallet.json")
    cl = ss.add_parser("claim", help="claim AUR from an HTLC by revealing the secret")
    cl.add_argument("--contract", required=True)
    cl.add_argument("--preimage", required=True)
    cl.add_argument("--file", default="aurion-wallet.json")
    rf = ss.add_parser("refund", help="refund an expired HTLC")
    rf.add_argument("--contract", required=True)
    rf.add_argument("--file", default="aurion-wallet.json")
    stt = ss.add_parser("status", help="show an HTLC (and its revealed secret once claimed)")
    stt.add_argument("--contract", required=True)
    bs = ss.add_parser("btc-script", help="build the matching Bitcoin HTLC")
    bs.add_argument("--hash", required=True)
    bs.add_argument("--recipient-btc", required=True, help="P2WPKH address that can claim with the secret")
    bs.add_argument("--refund-btc", required=True, help="P2WPKH address refunded after locktime")
    bs.add_argument("--locktime", type=int, required=True, help="absolute Bitcoin block height")

    args = ap.parse_args(argv)
    if args.cmd == "selftest":
        return selftest()
    if args.founder and args.network not in ("testnet", "regtest"):
        sys.exit("--founder is only for testnet/regtest; mainnet uses its published genesis founder")
    if args.founder and not ADDR_RE.match(args.founder):
        sys.exit("--founder must be an Aurion address (aur + 64 hex characters)")
    p = make_params(args.network, args.founder, args.allow_unaudited_mainnet)
    if args.network == "mainnet":
        print("WARNING: experimental unaudited mainnet; known consensus flaws remain. "
              "This is not a quantum-proof or independently reviewed currency.", file=sys.stderr)

    if args.cmd == "wallet":
        if args.action == "new":
            pw = None
            if args.encrypt:
                pw = getpass.getpass("New password: ")
                if pw != getpass.getpass("Repeat password: "):
                    sys.exit("passwords do not match")
            wl = Wallet.create(args.file, password=pw)
            print(f"address: {wl.address}\nsaved to {args.file}  (back it up; it cannot be recovered)")
        else:
            with open(args.file) as f:
                d = json.load(f)
            print(f"address: {d['address']}\nsignatures used: {d['next_index']}/{1 << d['height']}"
                  f"\nencrypted: {'enc' in d}")
    elif args.cmd == "plot":
        if args.action == "create":
            if not args.reward_address:
                sys.exit("--reward-address is required (your wallet address)")
            path = create_plot(args.dir, args.reward_address, args.size_mb)
            print(f"plot written: {path}\nstart mining with: aurion.py --network {args.network} "
                  + ("--allow-unaudited-mainnet " if args.network == "mainnet" else "")
                  + f"node --mine --plots {args.dir}")
        else:
            for lp in load_plots(args.dir):
                print(f"{lp.plot_id}  {lp.n * 36 / 2 ** 20:,.0f} MB  reward -> {lp.meta['owner']}")
    elif args.cmd == "node":
        run_node(p, args)
    elif args.cmd == "balance":
        a = http_json(node_url(args, p), f"/account/{args.address}")
        print(f"balance:   {fmt(a['balance'])}\nspendable: {fmt(a['spendable'])}")
        if a["locked"]:
            print(f"locked:    {fmt(a['locked'])}  (founder vesting)")
    elif args.cmd == "send":
        wl = Wallet.load(args.file)
        cli_send_tx(args, p, wl, "transfer", args.to, args.amount, args.fee, {})
    elif args.cmd == "info":
        print(json.dumps(http_json(node_url(args, p), "/info"), indent=1))
    elif args.cmd == "genesis":
        g = genesis_checkpoint(p)
        print(json.dumps(g["body"], indent=1))
        print("genesis hash:", cp_hash(g))
    elif args.cmd == "founder":
        print(f"founder address:    {p.founder or '(none on this network)'}")
        print(f"allocation:         {fmt(FOUNDER_ALLOCATION)} ({FOUNDER_ALLOCATION_BPS / 100:.2f} % of supply)")
        print(f"vesting:            linear over {p.vesting:,} checkpoints "
              f"(~{p.vesting * p.interval / 86400 / 365:.1f} years)" if p.vesting
              else "availability:       entire allocation available from genesis")
        print(f"mining supply:      {fmt(MINING_SUPPLY)}; first reward {fmt(p.r0)} per checkpoint")
    elif args.cmd == "swap":
        swap_cli(args, p)
    return 0


SWAP_HELP = """\
Experimental HTLC tools for test coins only. Do not use these tools for real
trades: the consensus and signature implementation have not been audited.
These tools generate scripts; they do not connect to an exchange or execute
a Bitcoin trade. Never send real BTC to a script produced by this release.

Test-only AUR<->BTC workflow (Alice has test AUR, Bob has test BTC):

 1. Alice:  aurion.py swap secret
            Keep the PREIMAGE private. Share the HASH with Bob.
 2. Alice:  aurion.py swap lock --to <Bob's aur address> --amount 100 --hash <HASH> --timeout 2880
            (2880 checkpoints is ~12 h on testnet; regtest has no wall-clock
            checkpoint interval.) Send Bob the contract id.
 3. Bob:    aurion.py swap status --contract <id>   -> check amount, hash and timeout.
            aurion.py swap btc-script --hash <HASH> --recipient-btc <Alice bc1q...>
                      --refund-btc <Bob's test address> --locktime <test BTC refund height>
            Calculate both timeouts using the actual network intervals. The BTC
            refund must occur earlier than the AUR refund, with enough margin
            for confirmations, clock uncertainty and claim transactions.
 4. Alice spends the BTC HTLC with the preimage. This publishes the preimage on Bitcoin.
 5. Bob:    aurion.py swap claim --contract <id> --preimage <PREIMAGE from Alice's BTC spend>
 If anyone walks away, each side refunds after its timeout (`swap refund` on Aurion).

The Bitcoin claim/refund transaction must be built with a wallet or library that
can spend custom P2WSH scripts (e.g. Bitcoin Core PSBT tooling or python-bitcointx).
"""


def swap_cli(args, p):
    c = args.swap_cmd
    if c == "secret":
        pre = secrets.token_bytes(32)
        print(f"PREIMAGE (keep secret): {pre.hex()}\nHASH (share):           {hashlib.sha256(pre).hexdigest()}")
    elif c == "btc-script":
        if not HEX64_RE.match(args.hash):
            sys.exit("hash must be 64 hex characters")
        s, addr = btc_htlc(args.hash, args.recipient_btc, args.refund_btc, args.locktime, p.btc_hrp)
        print(f"witness script: {s.hex()}\nP2WSH address:  {addr}")
        print("claim witness:  <sig> <pubkey> <preimage> 01 <witness script>")
        print(f"refund witness: <sig> <pubkey> (empty) <witness script>, nLockTime >= {args.locktime}, nSequence < 0xffffffff")
    elif c == "status":
        print(json.dumps(http_json(node_url(args, p), f"/htlc/{args.contract}"), indent=1))
    else:
        wl = Wallet.load(args.file)
        fee = MIN_FEE
        if c == "lock":
            h = http_json(node_url(args, p), "/info")["height"]
            tid, _ = cli_send_tx(args, p, wl, "htlc_lock", args.to, args.amount, fee,
                                 {"hashlock": args.hash, "timeout": h + args.timeout})
            print(f"contract id: {tid}")
        elif c == "claim":
            cli_send_tx(args, p, wl, "htlc_claim", "", 0, fee,
                        {"contract": args.contract, "preimage": args.preimage})
        elif c == "refund":
            cli_send_tx(args, p, wl, "htlc_refund", "", 0, fee, {"contract": args.contract})


# =============================================================================
# 10. SELF TEST
# =============================================================================
def selftest():
    ok = [0]

    def check(cond, label):
        if not cond:
            raise AssertionError("FAILED: " + label)
        ok[0] += 1
        print(f"  ok  {label}")

    tmp = tempfile.mkdtemp(prefix="aurion-test-")
    try:
        print("Signatures")
        k = MerkleKey(os.urandom(32), os.urandom(32), 3)
        sig = k.sign(b"m" * 32, 5)
        check(verify_sig(k.address, b"m" * 32, sig) == 5, "valid signature verifies")
        check(verify_sig(k.address, b"x" * 32, sig) is None, "wrong message rejected")
        bad = bytearray(bytes.fromhex(sig))
        bad[100] ^= 1
        check(verify_sig(k.address, b"m" * 32, bad.hex()) is None, "tampered signature rejected")
        check(verify_sig("aur" + "0" * 64, b"m" * 32, sig) is None, "wrong address rejected")

        print("Wallet encryption")
        ew = Wallet.create(os.path.join(tmp, "enc.json"), height=2, password="pw", progress=False)
        check(Wallet.load(ew.path, "pw").address == ew.address, "encrypted wallet round-trips")
        try:
            Wallet.load(ew.path, "nope")
            check(False, "wrong password rejected")
        except ValueError:
            check(True, "wrong password rejected")

        print("Ledger")
        founder = Wallet.create(os.path.join(tmp, "founder.json"), height=4, progress=False)
        alice = Wallet.create(os.path.join(tmp, "alice.json"), height=4, progress=False)
        miner = Wallet.create(os.path.join(tmp, "miner.json"), height=4, progress=False)
        p = make_params("regtest", founder.address)
        node = Node(p, os.path.join(tmp, "data"), log=lambda *a: None)
        check(node.account(founder.address)["balance"] == FOUNDER_ALLOCATION, "founder allocation in genesis")
        check(node.account(founder.address)["spendable"] == FOUNDER_ALLOCATION, "founder allocation available from genesis")

        lp = LocalPlot(create_plot(os.path.join(tmp, "plots"), miner.address, 0.2, progress=False))
        lp2 = LocalPlot(create_plot(os.path.join(tmp, "plots2"), alice.address, 0.2, progress=False))
        for x in (lp, lp2):
            st, _ = node.add_tx(make_register_tx(p, x, node.tx_parents(), -1))
            check(st == "ok", "plot registration accepted")
        for i in range(REG_DELAY + 1):
            check(node.try_produce([lp, lp2]) is not None, f"checkpoint {i + 1} produced")
        check(node.height() == REG_DELAY + 1, f"chain reached height {REG_DELAY + 1}")
        st = node.best_state()
        check(len(st.plots) == 2, "both plots registered on chain")
        bal_m = st.balances.get(miner.address, 0) + st.balances.get(alice.address, 0)
        check(bal_m == sum(p.reward(h) for h in range(1, node.height() + 1)), "miners received rewards")

        print("Fork choice")
        parent = node.best_state()
        c1 = node.build_checkpoint(parent, lp, int(time.time()))
        c2 = node.build_checkpoint(parent, lp2, int(time.time()))
        node.add_checkpoint(c1)
        node.add_checkpoint(c2)
        d1, d2 = node.states[cp_hash(c1)].dist, node.states[cp_hash(c2)].dist
        check(node.best == (cp_hash(c1) if d1 < d2 else cp_hash(c2)), "closest storage proof wins")
        forged = json.loads(json.dumps(c1))
        forged["body"]["proof"]["index"] = (forged["body"]["proof"]["index"] + 1) % lp.n
        check(node.add_checkpoint(forged)[0] == "invalid", "forged storage proof rejected")

        print("Transfers and founder allocation")
        rich = miner if node.best_state().balances.get(miner.address, 0) > \
            node.best_state().balances.get(alice.address, 0) else alice
        poor = alice if rich is miner else miner
        st = node.best_state()
        tx = make_tx(p, rich, "transfer", poor.address, 5 * COIN, MIN_FEE, {}, node.tx_parents(), -1)
        check(node.add_tx(tx)[0] == "ok", "transfer accepted to mempool")
        too_much = make_tx(p, founder, "transfer", alice.address, FOUNDER_ALLOCATION, MIN_FEE, {},
                           node.tx_parents(), -1)
        check(node.add_tx(too_much)[0] == "invalid", "founder cannot spend allocation plus an unbudgeted fee")
        h_next = node.height() + 1
        vested = FOUNDER_ALLOCATION - p.locked(founder.address, h_next)
        ok_tx = make_tx(p, founder, "transfer", alice.address, vested - MIN_FEE, MIN_FEE, {},
                        node.tx_parents(), founder.data["next_index"] - 1)
        check(node.add_tx(ok_tx)[0] == "ok", "founder can spend allocation less its transaction fee")
        before_p = node.best_state().balances.get(poor.address, 0)
        node.try_produce([lp, lp2])
        st = node.best_state()
        check(st.height == h_next, "checkpoint produced")
        check(tx_id(tx) in st.processed and tx_id(ok_tx) in st.processed, "DAG transactions confirmed")
        gained = st.balances.get(poor.address, 0) - before_p
        check(gained >= 5 * COIN, "recipient received transfer")
        check(st.balances[founder.address] == FOUNDER_ALLOCATION - vested, "founder balance correct")
        replay = node.add_tx(tx)
        check(replay[0] == "dup", "replayed transaction ignored")

        print("Atomic swap (HTLC)")
        pre = os.urandom(32)
        hl = hashlib.sha256(pre).hexdigest()
        lock = make_tx(p, rich, "htlc_lock", poor.address, 2 * COIN, MIN_FEE,
                       {"hashlock": hl, "timeout": st.height + 3}, node.tx_parents(),
                       st.last_idx.get(rich.address, -1))
        check(node.add_tx(lock)[0] == "ok", "HTLC lock accepted")
        node.try_produce([lp, lp2])
        cid = tx_id(lock)
        check(node.best_state().htlcs[cid]["state"] == "open", "HTLC open on chain")
        wrong = make_tx(p, poor, "htlc_claim", "", 0, MIN_FEE, {"contract": cid, "preimage": os.urandom(32).hex()},
                        node.tx_parents(), node.best_state().last_idx.get(poor.address, -1))
        node.add_tx(wrong)
        node.try_produce([lp, lp2])
        check(node.best_state().htlcs[cid]["state"] == "open", "wrong preimage cannot claim")
        claim = make_tx(p, poor, "htlc_claim", "", 0, MIN_FEE, {"contract": cid, "preimage": pre.hex()},
                        node.tx_parents(), node.best_state().last_idx.get(poor.address, -1))
        check(node.add_tx(claim)[0] == "ok", "claim accepted")
        node.try_produce([lp, lp2])
        c = node.best_state().htlcs[cid]
        check(c["state"] == "claimed" and c["preimage"] == pre.hex(), "claimed; secret now public on chain")

        st = node.best_state()
        lock2 = make_tx(p, rich, "htlc_lock", poor.address, COIN, MIN_FEE,
                        {"hashlock": hl, "timeout": st.height + 2}, node.tx_parents(),
                        st.last_idx.get(rich.address, -1))
        node.add_tx(lock2)
        node.try_produce([lp, lp2])
        node.try_produce([lp, lp2])
        st = node.best_state()
        ref = make_tx(p, rich, "htlc_refund", "", 0, MIN_FEE, {"contract": tx_id(lock2)},
                      node.tx_parents(), st.last_idx.get(rich.address, -1))
        node.add_tx(ref)
        node.try_produce([lp, lp2])
        check(node.best_state().htlcs[tx_id(lock2)]["state"] == "refunded", "expired HTLC refunded")

        print("Supply")
        st = node.best_state()
        locked_in_htlc = sum(x["amount"] for x in st.htlcs.values() if x["state"] == "open")
        total = sum(st.balances.values()) + locked_in_htlc
        check(total == FOUNDER_ALLOCATION + st.minted, "no coins created or destroyed")
        check(FOUNDER_ALLOCATION + MINING_SUPPLY == MAX_SUPPLY, "founder + mining = 21,000,000 AUR")
        q = make_params("regtest", founder.address)
        emitted = sum(q.halving * (q.r0 >> e) for e in range(64))
        check(emitted <= MINING_SUPPLY, "halving schedule never exceeds the cap")

        print("Persistence")
        best = node.best
        node.db.close()
        node2 = Node(p, os.path.join(tmp, "data"), log=lambda *a: None)
        check(node2.best == best, "node reloads the same chain from disk")

        print("Bitcoin HTLC script")
        a1 = segwit_encode("bc", 0, bytes(range(20)))
        a2 = segwit_encode("bc", 0, bytes(range(20, 40)))
        check(segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")[1].hex()
              == "751e76e8199196d454941c45d1b3a323f1433bd6", "BIP173 test vector decodes")
        s, addr = btc_htlc(hl, a1, a2, 900_000, "bc")
        check(addr.startswith("bc1q") and len(addr) == 62, "P2WSH swap address generated")
        check(bytes.fromhex(hl) in s, "script commits to the hashlock")

        print(f"\nAll {ok[0]} checks passed.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# =============================================================================
# KNOWN LIMITATIONS (read before launching with real value)
# =============================================================================
# * Not audited. Get an independent security review before mainnet.
# * Plot entries are fast to recompute, so a well-equipped attacker could
#   trade computation for storage. Production PoVC should use memory-hard or
#   proof-of-replication plotting.
# * The checkpoint producer can bias the next challenge slightly by choosing
#   among its own valid proofs. A VDF or beacon would remove this.
# * Fork choice is heaviest-chain; finality is REORG_LIMIT checkpoints.
#   Low-hashpower launch phases are vulnerable to a large-storage attacker.
# * Ledger state is held in memory; fine for thousands of accounts, not millions.
# * The HTTP gossip layer has no encryption, peer scoring or DoS protection.
# * Signatures are stateful: never restore an old wallet backup and keep
#   sending from it, or a one-time key may be reused. Prefer a new wallet.
#   File locking protects cooperating writers of the same local wallet file;
#   separate copies, browser imports, other devices and rollback remain unsafe.
# * Receipt history is bounded to the processed-transaction window. Unknown
#   receipts must never be credited as exchange deposits. Public infrastructure,
#   operational finality policy and a reviewed indexer are not included.
# =============================================================================

if __name__ == "__main__":
    sys.exit(main())
