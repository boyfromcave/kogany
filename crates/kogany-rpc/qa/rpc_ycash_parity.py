#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany's stock RPC answers against ycash6's, field by field, on one Ycash regtest chain (W1-Y6).

    python crates/kogany-rpc/qa/rpc_ycash_parity.py --zakurad <zakurad built with --features ycash> \\
        [--ycash6-bin $WS/wt/.bin/ycash6-65cb4ae0f] [--workdir DIR] [--keep]

It starts a ycashd and a zakurad on Ycash regtest with every upgrade through Canopy at height 1
(the `-nuparams` set the ycash6 suites pass, `YCASH_UPGRADE_ARGS`), mines on ycashd and feeds each
block to zakurad through `submitblock`, so both serve the same chain. It then asks both nodes the
calls of the two clients that read kogany through stock RPC (plan W1-Y6, survey B §1 row 19):

- lightwalletd-dd: `getblockchaininfo`, `getinfo`, `getblock` (verbosity 0, 1, 2; by hash and by
  height), `getrawtransaction` (0, 1), `getrawmempool`, `gettxout`, `sendrawtransaction`,
  `z_gettreestate`, `getaddresstxids`, `getaddressbalance`, `getaddressutxos`;
- yolo: `getblocktemplate`, `submitblock`, `validateaddress`, `getblockchaininfo`;

and `getblocksubsidy`. Every kogany template is also checked by ycashd in proposal mode (consensus
validity without proof of work), and its coinbase outputs, amounts and scripts, are compared with
ycashd's own template's.

Every difference must be listed in `ACCEPTED` with its class and reason: `wallet` (ycashd answers
from its wallet; kogany has none, plan K-3, and the wallet in front of it adds these), `zakura`
(an upstream Zakura shape that is not network-specific: Zakura's documented extension or
omission against zcashd, left as upstream has it, plan §4.2 rule 2), `derived` (a value computed
from bytes that legitimately differ, such as the coinbase input script), `chunk` (owned by
another chunk, which is named). An unlisted difference fails the run. A number is compared by
value, so `1` and `1.0` are equal. The table of differences is printed at the end, and with
`--json` written as JSON.

Stdlib only.
"""

import argparse
import base64
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

# The shared ycash6 build at 65cb4ae0f (the harness chunk's), under the workspace root `$WS`.
DEFAULT_YCASH6_BIN = os.path.join(os.getenv('WS', ''), 'wt', '.bin', 'ycash6-65cb4ae0f')

# ycash6 qa/rpc-tests/test_framework/util.py:298-299 and yellowback_util.py:125-137.
NUPARAMS = ['5ba81b19', '76b809bb', '374d694f', '8e471bd6', '66314da3', '19bd2d2f']
ACTIVATION_KEYS = ['Overwinter', 'Sapling', 'Ycash', 'Blossom', 'Heartwood', 'Canopy']
YDF_MANDATE_END = 5          # ycash6 src/chainparams.cpp:777
COINBASE_MATURITY = 100
SOLUTION_BYTES = 36          # Equihash (48, 5) on regtest: 2^5 * (48/6 + 1) / 8

# (method regex, path regex, class, reason). A path is `.field`, `.list[i]`, `!error` for the
# error member of an answer, or `=answer` for the whole answer.
ACCEPTED = [
    # getblockchaininfo
    ('getblockchaininfo', r'\.initial_block_download_complete$', 'zakura',
     'a zcashd 6.x field Zakura does not serve; no client reads it'),
    ('getblockchaininfo', r'\.chainwork$', 'zakura',
     'Zakura reports chainwork as 0 (methods.rs GetBlockchainInfoResponse); no client reads it'),
    ('getblockchaininfo', r'\.size_on_disk$', 'zakura', 'a different database'),
    ('getblockchaininfo', r'\.transactions$', 'zakura', 'a zcashd 6.x field Zakura does not serve'),
    ('getblockchaininfo|getblock', r'\.valuePools(\[\d\]\.monitored)?$', 'zakura',
     'Zakura adds the lockbox and ironwood pools (zero on Ycash) and reports monitored=false'),
    ('getblockchaininfo|getblock', r'\.chainSupply\.monitored$', 'zakura',
     'Zakura reports monitored=false'),
    ('getblockchaininfo', r'\.softforks$', 'zakura', 'BIP34/66/65 counters Zakura does not serve'),
    ('getblockchaininfo', r'\.upgrades\.[0-9a-f]{8}\.info$', 'zakura',
     'Zakura omits the per-upgrade info URL for every upgrade; no client reads it'),
    ('getblockchaininfo', r'\.fullyNotified$', 'zakura', 'a zcashd notification flag'),
    ('getblockchaininfo', r'\.nsmValueBalanceZat$', 'zakura', 'ZIP 234 balance, zero on Ycash'),
    ('getblockchaininfo', r'\.estimatedheight$', 'derived',
     'a clock-based estimate from the tip time; on regtest both are far above the tip'),
    ('getblockchaininfo', r'\.headers$', 'zakura',
     'Zakura counts the header chain it has validated; equal once synced'),
    # getinfo: lightwalletd-dd reads build and subversion as opaque strings (common.go:85-88).
    ('getinfo', r'\.(version|build|subversion)$', 'zakura', 'a different implementation'),
    ('getinfo', r'\.protocolversion$', 'chunk',
     'W1-Y5 (p2p): the Ycash protocol version (270200) is the P2P chunk'),
    ('getinfo', r'\.(walletversion|balance|keypoololdest|keypoolsize|paytxfee)$', 'wallet',
     'wallet fields'),
    ('getinfo', r'\.(timeoffset|proxy)$', 'zakura', 'zcashd node fields Zakura does not serve'),
    ('getinfo', r'\.(errors|errorstimestamp)$', 'zakura', 'node-local status'),
    ('getinfo', r'\.(connections|relayfee)$', 'zakura', 'node-local status'),
    # getblock
    ('getblock', r'\.(authdataroot|chainhistoryroot|anchor|blockfee|chainwork)$', 'zakura',
     'zcashd 6.x block fields Zakura does not serve; lightwalletd-dd reads hex, height, tx'),
    ('getblock', r'\.chainSupply\.valueDelta(Zat)?$', 'zakura', 'per-block deltas Zakura omits'),
    ('getblock', r'\.valuePools\[\d\]\.valueDelta(Zat)?$', 'zakura', 'per-block deltas Zakura omits'),
    ('getblock', r'\.trees\.sapling$', 'zakura',
     'Zakura omits the Sapling tree size when the tree is empty'),
    ('getblock', r'\.nTx$', 'zakura', 'a Zakura extension'),
    ('getblock', r'\.tx\[\d+\]\.(authdigest|in_active_chain|orchard)$', 'zakura',
     'transaction object fields, as in getrawtransaction'),
    ('getblock', r'\.tx\[\d+\]\.vout\[\d+\]\.valueSat$', 'zakura',
     'the zcashd alias of valueZat; Zakura serves valueZat'),
    ('getblock', r'\.tx\[\d+\]\.(blockhash|confirmations|blocktime|time|height)$', 'zakura',
     'Zakura adds the in-block context fields inside getblock 2'),
    ('getblock', r'\.tx\[\d+\]\.vin\[\d+\]\.(value|valueZat|valueSat|address)$', 'zakura',
     'zcashd -insightexplorer spent-output fields Zakura does not serve'),
    # getrawtransaction: lightwalletd-dd reads hex and height (common.go:115-119).
    ('getrawtransaction', r'\.authdigest$', 'zakura', 'a v5 field; Zakura omits it for v4'),
    ('getrawtransaction', r'\.vout\[\d+\]\.valueSat$', 'zakura', 'the zcashd alias of valueZat'),
    ('getrawtransaction', r'\.(in_active_chain|orchard)$', 'zakura', 'Zakura extensions'),
    ('getrawtransaction', r'\.vin\[\d+\]\.(value|valueZat|valueSat|address)$', 'zakura',
     'zcashd -insightexplorer spent-output fields Zakura does not serve'),
    # gettxout
    ('gettxout', r'\.(version|coinbase)$', 'zakura', 'zcashd fields Zakura does not serve'),
    # z_gettreestate: lightwalletd-dd reads height, hash, time, sapling (common.go:103-113).
    ('z_gettreestate', r'\.sprout$', 'zakura',
     'Zakura does not serve the Sprout tree; lightwalletd-dd does not read it'),
    ('z_gettreestate', r'\.(orchard|ironwood)$', 'zakura', 'empty pools Zakura always reports'),
    ('z_gettreestate', r'\.sapling\.commitments\.finalRoot$', 'zakura',
     'zcashd 6.x adds the root beside finalState; lightwalletd-dd reads finalState'),
    # getaddressbalance
    ('getaddressbalance', r'\.txcount$', 'zakura', 'a zcashd 6.x field; lightwalletd-dd reads balance'),
    # getblocksubsidy: Zcash-only totals, zero on Ycash.
    ('getblocksubsidy', r'\.(fundingstreamstotal|lockboxtotal)$', 'zakura',
     'Zcash ZIP 207/271 totals, always zero on Ycash'),
    # getblocktemplate
    ('getblocktemplate', r'\.capabilities$', 'zakura', 'Zakura adds submitsolution'),
    ('getblocktemplate', r'\.(maxtime|workid|submitold)$', 'zakura', 'Zakura extensions'),
    ('getblocktemplate', r'\.longpollid$', 'zakura', "Zakura's long-poll id encoding"),
    ('getblocktemplate', r'\.curtime$', 'derived', 'the clock at the call; compared within 120 s'),
    ('getblocktemplate', r'\.defaultroots\.(authdataroot|blockcommitmentshash)$', 'zakura',
     'NU5 fields Zakura always sends; before NU5 its blockcommitmentshash is the chain history '
     'root, the header value, which yolo reads first (yolo src/template.rs:87-99)'),
    ('getblocktemplate', r'\.defaultroots\.merkleroot$|\.coinbasetxn\.(data|hash|authdigest)$',
     'derived', 'the coinbase input script differs: Zakura tags it and adds random data, and sets '
     'the expiry height; the outputs are compared in coinbase.outputs'),
    ('getblocktemplate', r'\.transactions\[\d+\]\.required$', 'zakura',
     'Zakura sends the optional BIP 22 required=false on every non-coinbase entry'),
    ('getblocktemplate', r'\.transactions\[\d+\]\.depends$', 'zakura',
     "Zakura's mempool tracks no in-template dependencies"),
    ('getblocktemplate', r'\.coinbase\.(script_sig_tail|expiry_height)$', 'derived',
     "Zakura's coinbase tag, random data and expiry height"),
    ('getblocktemplate', r'\.yellowback$', 'chunk', 'W8-b (coinbase-tag): the YED template info'),
    ('getblocktemplate', r'\.coinbaseaux$', 'chunk', 'W8-b (coinbase-tag): the YED coinbase flags'),
    # submitblock
    ('submitblock', r'=answer$|!error$', 'chunk',
     'W7-e (rpc-parity) maps the rejection strings and the -22 decode error; accept is null on both'),
    # sendrawtransaction errors
    ('sendrawtransaction', r'!error$', 'chunk', 'W7-e (rpc-parity): the -26/-25/-27 reject texts; '
     'at ycashd\'s default fee, kogany\'s ZIP 317 mempool refuses what ycashd takes (finding F-2, '
     'the pre-Vault Ycash fee policy has no chunk yet)'),
    # yed_getinfo
    ('yed_getinfo', r'.*', 'chunk', 'W7-b: the yed_* read RPCs (kogany-rpc/src/yed/)'),
    # validateaddress: ycashd adds wallet fields from DescribeAddressVisitor (misc.cpp).
    ('validateaddress', r'\.(ismine|iswatchonly|pubkey|iscompressed|account)$', 'wallet',
     'wallet fields'),
    ('validateaddress', r'\.(script|hex|addresses|sigsrequired)$', 'wallet',
     'the wallet\'s description of a P2SH redeem script it knows'),
    ('validateaddress', r'\.isscript$', 'wallet',
     'ycashd sends isscript from its wallet only; Zakura always sends it'),
]

# The fields the clients read (survey B row 19; lightwalletd-dd common/common.go:74-140, yolo
# src/template.rs:14-67 and src/rpc.rs:208-214), and the coinbase fields every template must agree
# on, as full-path patterns: a difference here fails the run even where an ACCEPTED row matches.
CLIENT_FIELDS = {
    'getblockchaininfo': r'\.(chain|blocks|bestblockhash|upgrades(\.[0-9a-f]{8}(\.(name|activationheight|status))?)?|consensus(\.\w+)?)$',
    'getblock': r'\.(hash|height|time|bits|previousblockhash|finalsaplingroot|tx(\[\d+\](\.(txid|hex))?)?)$|=answer$',
    'getrawtransaction': r'\.(hex|height|txid|version|expiryheight|vout(\[\d+\]\.(value|valueZat|n|scriptPubKey(\.\w+)?))?)$|=answer$',
    'z_gettreestate': r'\.(height|hash|time|sapling(\.commitments(\.finalState)?|\.skipHash)?)$',
    'getaddressbalance': r'\.balance$',
    'getaddressutxos': r'.*',
    'getaddresstxids': r'.*',
    'getrawmempool': r'.*',
    'gettxout': r'\.(value|confirmations|bestblock|scriptPubKey(\.\w+)?)$|=answer$',
    'getblocktemplate': r'\.(version|previousblockhash|blockcommitmentshash|lightclientroothash|'
                        r'finalsaplingroothash|transactions(\[\d+\]\.(data|hash|fee))?|target|bits|height|'
                        r'mintime|sizelimit|sigoplimit|noncerange|mutable|defaultroots\.chainhistoryroot|'
                        r'coinbasetxn\.(fee|sigops|foundersreward|required)|'
                        r'coinbase\.(header|versiongroupid|height_push|outputs.*|locktime)|proposal.*)$',
    'validateaddress': r'\.(isvalid|address|scriptPubKey)$',
    'getblocksubsidy': r'\.(miner|founders|totalblocksubsidy)$',
}

WALLET_ONLY = {
    'z_sendmany': 'lightwalletd-dd uses it on the regtest faucet path; kogany has no wallet (K-3)',
    'dumpprivkey': 'lightwalletd-dd regtest helper; wallet',
    'yed_mint': 'lightwalletd-dd regtest helper; a YED wallet RPC (W7-b/yewd)',
}


class RpcError(Exception):
    pass


class Node:
    """A JSON-RPC 1.0 client that returns (result, error) and never raises on an RPC error."""

    def __init__(self, name, port, auth=None):
        self.name, self.port, self.auth = name, port, auth

    def call(self, method, *params):
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        req = urllib.request.Request('http://127.0.0.1:%d/' % self.port, body, {'Content-Type': 'application/json'})
        if self.auth:
            req.add_header('Authorization', 'Basic ' + base64.b64encode(self.auth.encode()).decode())
        try:
            raw = urllib.request.urlopen(req, timeout=300).read()
        except urllib.error.HTTPError as e:
            raw = e.read()
        except (urllib.error.URLError, ConnectionError) as e:
            raise RpcError('%s: %s: %s' % (self.name, method, e))
        answer = json.loads(raw)
        return answer.get('result'), answer.get('error')

    def ok(self, method, *params):
        result, error = self.call(method, *params)
        if error:
            raise RpcError('%s: %s%r: %s' % (self.name, method, params, error))
        return result


def wait_up(node, proc, what, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RpcError('%s exited with %s' % (what, proc.returncode))
        try:
            _, error = node.call('getblockcount')
            if not error:
                return
        except RpcError:
            pass
        time.sleep(0.5)
    raise RpcError('%s did not answer within %d s' % (what, timeout))


# Coinbase decoding (transparent part of a v4 transaction).

def read_compact(b, i):
    n = b[i]
    if n < 0xfd:
        return n, i + 1
    width = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]
    return int.from_bytes(b[i + 1:i + 1 + width], 'little'), i + 1 + width


def decode_coinbase(hexdata):
    """The fields of a v4 coinbase that a template must agree on: version, outputs, and the
    height push at the start of the input script."""
    b = bytes.fromhex(hexdata)
    header = int.from_bytes(b[0:4], 'little')
    group = b[4:8].hex()
    i = 8
    nin, i = read_compact(b, i)
    if nin != 1:
        raise ValueError('a coinbase has one input')
    i += 36
    slen, i = read_compact(b, i)
    script_sig = b[i:i + slen]
    i += slen + 4
    nout, i = read_compact(b, i)
    outputs = []
    for _ in range(nout):
        value = int.from_bytes(b[i:i + 8], 'little')
        i += 8
        plen, i = read_compact(b, i)
        outputs.append({'value': value, 'script': b[i:i + plen].hex()})
        i += plen
    lock_time = int.from_bytes(b[i:i + 4], 'little')
    expiry = int.from_bytes(b[i + 4:i + 8], 'little')
    # BIP 34: a small height is one opcode (OP_1..OP_16), a larger one a push of its bytes.
    first = script_sig[0]
    width = 1 if first == 0 or 0x51 <= first <= 0x60 else 1 + first
    return {
        'header': header,
        'versiongroupid': group,
        'height_push': script_sig[:width].hex(),
        'script_sig_tail': script_sig[width:].hex(),
        'outputs': outputs,
        'locktime': lock_time,
        'expiry_height': expiry,
    }


def internal(hex_display):
    return bytes.fromhex(hex_display)[::-1]


def block_from_template(t):
    """A block for proposal mode: the template's header fields, a zero nonce and an all-zero
    solution of the regtest size, then the coinbase and the template's transactions."""
    header = (int(t['version']).to_bytes(4, 'little')
              + internal(t['previousblockhash'])
              + internal(t['defaultroots']['merkleroot'])
              + internal(t['blockcommitmentshash'])
              + int(t['curtime']).to_bytes(4, 'little')
              + int(t['bits'], 16).to_bytes(4, 'little')
              + bytes(32)
              + bytes([SOLUTION_BYTES]) + bytes(SOLUTION_BYTES))
    txs = [t['coinbasetxn']['data']] + [tx['data'] for tx in t['transactions']]
    count = len(txs)
    assert count < 0xfd
    return header.hex() + bytes([count]).hex() + ''.join(txs)


# Comparison.

def same_value(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return a == b


def diff(a, b, path=''):
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in list(a) + [k for k in b if k not in a]:
            p = '%s.%s' % (path, k)
            if k not in b:
                out.append((p, 'ycash6 only', a[k], None))
            elif k not in a:
                out.append((p, 'kogany only', None, b[k]))
            else:
                out += diff(a[k], b[k], p)
    elif isinstance(a, list) and isinstance(b, list) and path.split('.')[-1] not in ('capabilities',):
        if len(a) != len(b):
            out.append((path, 'length %d vs %d' % (len(a), len(b)), a, b))
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, '%s[%d]' % (path, i))
    elif not same_value(a, b):
        out.append((path, 'value', a, b))
    return out


def short(v):
    s = json.dumps(v, sort_keys=True)
    return s if len(s) <= 70 else s[:67] + '...'


class Report:
    def __init__(self):
        self.rows = []        # (method, call, path, kind, ycash6, kogany, class, reason)
        self.calls = 0

    def classify(self, method, path):
        if method in CLIENT_FIELDS and re.fullmatch(CLIENT_FIELDS[method], path):
            return 'FAIL', 'a field the client reads'
        for m, p, cls, reason in ACCEPTED:
            if re.fullmatch(m, method) and re.search(p, path):
                return cls, reason
        return 'FAIL', 'not accepted'

    def add(self, method, call, path, kind, a, b):
        cls, reason = self.classify(method, path)
        self.rows.append((method, call, path, kind, a, b, cls, reason))

    def compare(self, method, call, ra, rb):
        self.calls += 1
        (a, ea), (b, eb) = ra, rb
        if ea or eb:
            if bool(ea) != bool(eb) or (ea or {}).get('code') != (eb or {}).get('code'):
                self.add(method, call, '!error', 'error', ea, eb)
            return
        if isinstance(a, dict) and isinstance(b, dict) or isinstance(a, list) and isinstance(b, list):
            for path, kind, x, y in diff(a, b):
                self.add(method, call, path, kind, x, y)
        elif not same_value(a, b):
            self.add(method, call, '=answer', 'value', a, b)

    def failures(self):
        return [r for r in self.rows if r[6] == 'FAIL']

    def print(self):
        seen = {}
        for r in self.rows:
            key = (r[0], r[2], r[6])
            seen.setdefault(key, []).append(r)
        print('\n%-18s %-48s %-8s %s' % ('method', 'field', 'class', 'ycash6 | kogany  (reason)'))
        for (method, path, cls), rows in seen.items():
            r = rows[0]
            print('%-18s %-48s %-8s %s | %s  (%s)%s' % (
                method, path, cls, short(r[4]), short(r[5]), r[7],
                '  x%d' % len(rows) if len(rows) > 1 else ''))
        print('\n%d calls compared, %d differing fields (%d distinct), %d not accepted'
              % (self.calls, len(self.rows), len(seen), len(self.failures())))


# The run.

def start_ycashd(bindir, workdir, port, rpcport, mineraddress=None):
    datadir = os.path.join(workdir, 'ycashd')
    os.makedirs(datadir, exist_ok=True)
    with open(os.path.join(datadir, 'ycash.conf'), 'w') as f:
        f.write('regtest=1\nshowmetrics=0\nrpcuser=u\nrpcpassword=p\nport=%d\nrpcport=%d\nlistenonion=0\n'
                % (port, rpcport))
    args = [os.path.join(bindir, 'ycashd'), '-datadir=' + datadir, '-discover=0', '-listen=0',
            '-txindex', '-insightexplorer', '-experimentalfeatures',
            '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
    # -lightwalletd alone crashes ycash6 at the first block (CInsightExplorerDB is created only
    # under -insightexplorer, init.cpp:2016,2080; reported in the W1-Y6 findings).
    args += ['-nuparams=%s:1' % b for b in NUPARAMS]
    if mineraddress:
        args.append('-mineraddress=' + mineraddress)
    log = open(os.path.join(workdir, 'ycashd.out'), 'a')
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)


def zakurad_toml(workdir, p2p, rpc, v2, miner_address):
    root = os.path.join(workdir, 'zakurad')
    heights = '\n'.join('%s = 1' % k for k in ACTIVATION_KEYS)
    return '''[network]
listen_addr = "127.0.0.1:{p2p}"
initial_testnet_peers = []
p2p_stack = "legacy"
cache_dir = "{root}/network"
identity_dir = "{root}/identity"

[network.network]
regtest = true

[network.network.params.activation_heights]
{heights}

[network.zakura]
listen_addr = "127.0.0.1:{v2}"

[rpc]
listen_addr = "127.0.0.1:{rpc}"
enable_cookie_auth = false
cookie_dir = "{root}/rpc"

[state]
cache_dir = "{root}/state"
ephemeral = false

[mempool]
debug_enable_at_height = 0

[mining]
internal_miner = false
miner_address = "{miner}"

[tracing]
use_color = false
filter = "info"
'''.format(p2p=p2p, rpc=rpc, v2=v2, root=root, heights=heights, miner=miner_address)


def start_zakurad(binary, workdir, toml):
    path = os.path.join(workdir, 'zakurad.toml')
    with open(path, 'w') as f:
        f.write(toml)
    log = open(os.path.join(workdir, 'zakurad.out'), 'a')
    return subprocess.Popen([binary, '-c', path, 'start'], stdout=log, stderr=subprocess.STDOUT)


def stop(proc):
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(30)
        except subprocess.TimeoutExpired:
            proc.kill()


class Run:
    def __init__(self, y, z, report):
        self.y, self.z, self.report = y, z, report

    def both(self, method, *params):
        self.report.compare(method, json.dumps(list(params))[:60], self.y.call(method, *params),
                            self.z.call(method, *params))

    def mine(self, n=1):
        """Mine `n` blocks on ycashd and feed each to kogany; both tips must then agree."""
        for h in self.y.ok('generate', n):
            raw = self.y.ok('getblock', h, 0)
            res = self.z.ok('submitblock', raw)
            if res is not None:
                raise RpcError('kogany refused block %s: %r' % (h, res))
        self.sync()

    def sync(self, timeout=60):
        want = self.y.ok('getbestblockhash')
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.z.ok('getbestblockhash') == want:
                return
            time.sleep(0.2)
        raise RpcError('kogany tip is not %s' % want)

    def template(self):
        """Both templates; kogany's checked by ycashd and by kogany in proposal mode, and the
        coinbase outputs compared."""
        ty, tz = self.y.ok('getblocktemplate'), self.z.ok('getblocktemplate')
        call = 'height %d' % ty['height']
        if abs(int(ty['curtime']) - int(tz['curtime'])) > 120:
            self.report.add('getblocktemplate', call, '.curtime', 'beyond 120 s', ty['curtime'], tz['curtime'])
        self.report.compare('getblocktemplate', call, (ty, None), (tz, None))
        cy, cz = decode_coinbase(ty['coinbasetxn']['data']), decode_coinbase(tz['coinbasetxn']['data'])
        self.report.compare('getblocktemplate', call, ({'coinbase': cy}, None), ({'coinbase': cz}, None))
        block = block_from_template(tz)
        for node in (self.y, self.z):
            verdict, error = node.call('getblocktemplate', {'mode': 'proposal', 'data': block})
            self.report.calls += 1
            if error or verdict is not None:
                self.report.add('getblocktemplate', call, '.proposal(%s)' % node.name, 'refused',
                                None, error or verdict)
        return ty, tz


def wait_balance(y, amount, timeout=30):
    """ycashd's wallet sees a mined coinbase a moment after `generate` returns."""
    deadline = time.time() + timeout
    while y.ok('getbalance') < amount:
        if time.time() > deadline:
            raise RpcError('ycash6 wallet balance stays below %s' % amount)
        time.sleep(0.5)


def spend_with_zip317_fee(y, address):
    """Spend one mature transparent coin of ycashd's wallet to `address`, one input and one
    output, paying the ZIP 317 fee (two grace actions at 5,000 zatoshis), and send it with
    `allowhighfees`: ycashd's wallet would refuse that fee as above four times its conventional
    fee. Returns the txid."""
    # The wallet may still list a coin its last block spent; ask the chain.
    coin = next(u for u in y.ok('listunspent', 101) if u['spendable'] and u['amount'] > 1
                and y.ok('gettxout', u['txid'], u['vout'], False) is not None)
    out = {address: float(round(coin['amount'] - 0.0001, 8))}
    unsigned = y.ok('createrawtransaction', [{'txid': coin['txid'], 'vout': coin['vout']}], out)
    signed = y.ok('signrawtransaction', unsigned)
    if not signed['complete']:
        raise RpcError('ycash6 could not sign the ZIP 317 spend: %r' % signed)
    return y.ok('sendrawtransaction', signed['hex'], True)


def run(args):
    report = Report()
    workdir = args.workdir or tempfile.mkdtemp(prefix='rpc-ycash-parity-')
    os.makedirs(workdir, exist_ok=True)
    base = args.port_base
    y = Node('ycash6', base + 1, 'u:p')
    z = Node('kogany', base + 11)
    procs = []
    try:
        # A first ycashd start creates the wallet whose address both nodes then mine to.
        procs.append(start_ycashd(args.ycash6_bin, workdir, base, base + 1))
        wait_up(y, procs[-1], 'ycashd')
        miner = y.ok('getnewaddress')
        y.ok('stop')
        procs[-1].wait(60)
        procs[-1] = start_ycashd(args.ycash6_bin, workdir, base, base + 1, miner)
        wait_up(y, procs[-1], 'ycashd')
        procs.append(start_zakurad(args.zakurad, workdir, zakurad_toml(workdir, base + 10, base + 11, base + 12, miner)))
        wait_up(z, procs[-1], 'zakurad')

        r = Run(y, z, report)
        r.both('getblockchaininfo')

        # Templates across the mandatory YDF (heights 2-4) and the optional one (5 on). ycashd
        # serves no template at the genesis tip: a 2011 genesis keeps it in initial block
        # download (-10) until the first block.
        r.mine()
        for _ in range(YDF_MANDATE_END + 1):
            r.template()
            r.both('getblocksubsidy')
            r.mine()
        r.mine(COINBASE_MATURITY + 2)

        # A spend at ycashd's default fee: kogany's mempool refuses it (ZIP 317, finding F-2),
        # the block that mines it is valid on both.
        recipient = y.ok('getnewaddress')
        wait_balance(y, 3)
        default_fee_txid = y.ok('sendtoaddress', recipient, 1.5)
        raw = y.ok('getrawtransaction', default_fee_txid, 0)
        r.report.compare('sendrawtransaction', 'default fee', y.call('sendrawtransaction', raw),
                         z.call('sendrawtransaction', raw))
        r.mine()

        # A spend paying the ZIP 317 fee, which ycashd takes with allowhighfees: in both
        # mempools, in both templates, then mined.
        txid = spend_with_zip317_fee(y, recipient)
        raw = y.ok('getrawtransaction', txid, 0)
        r.both('sendrawtransaction', raw)
        r.both('getrawmempool')
        r.template()
        r.mine()
        tip = y.ok('getblockcount')

        # lightwalletd-dd's reads at the common tip.
        r.both('getblockchaininfo')
        r.both('getinfo')
        for h in (1, 2, YDF_MANDATE_END, tip):
            bh = y.ok('getblockhash', h)
            for verbosity in (0, 1, 2):
                r.both('getblock', bh, verbosity)
            r.both('getblock', str(h), 1)
            r.both('z_gettreestate', str(h))
            r.both('z_gettreestate', bh)
            cb = y.ok('getblock', bh, 1)['tx'][0]
            r.both('getrawtransaction', cb, 0)
            r.both('getrawtransaction', cb, 1)
            r.both('gettxout', cb, 0)
            r.both('gettxout', cb, 1)
        r.both('getrawtransaction', txid, 0)
        r.both('getrawtransaction', txid, 1)
        r.both('gettxout', txid, 0)
        r.both('gettxout', txid, 1)
        ydf = y.ok('getblock', y.ok('getblockhash', 1), 2)['tx'][0]['vout'][1]['scriptPubKey']['addresses'][0]
        for addr in (miner, recipient, ydf):
            q = {'addresses': [addr]}
            r.both('getaddressbalance', q)
            r.both('getaddressutxos', q)
            r.both('getaddresstxids', q)
            r.both('getaddresstxids', {'addresses': [addr], 'start': 1, 'end': tip})
        r.both('getrawmempool')
        r.both('sendrawtransaction', raw)
        r.both('yed_getinfo')

        # getblocksubsidy across the schedule.
        for h in (1, YDF_MANDATE_END - 1, YDF_MANDATE_END, 150, tip):
            r.both('getblocksubsidy', h)

        # yolo's reads: validateaddress (P2PKH, P2SH, foreign and invalid), submitblock.
        p2sh = y.ok('addmultisigaddress', 1, [miner])
        for addr in (miner, recipient, ydf, p2sh,
                     's1hfWJ4ej1H3s8XCUb7YnrU68K64AsGVUHE',   # Ycash mainnet P2PKH
                     's3KAgqRpsVPXiWCxsc8Nir6wQ4CKdMcT97G',   # Ycash mainnet P2SH (a founders' script)
                     's2Xi8gr2eXXT2f8Jx8axGD2qwutsQPwjNYG',   # Ycash testnet P2SH
                     't1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs',   # Zcash mainnet
                     'tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU',   # Zcash testnet
                     y.ok('z_getnewaddress', 'sapling'),
                     'not-an-address'):
            r.both('validateaddress', addr)
        tip_raw = y.ok('getblock', y.ok('getbestblockhash'), 0)
        r.both('submitblock', tip_raw)
        r.both('submitblock', '00')
        r.template()
        r.both('getblockchaininfo')
    finally:
        for p in reversed(procs):
            stop(p)
        if not args.keep and not args.workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    return report, workdir


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--zakurad', default=os.getenv('KOGANY_BIN'), help='zakurad built with --features ycash')
    ap.add_argument('--ycash6-bin', default=DEFAULT_YCASH6_BIN, help='directory holding ycashd')
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--keep', action='store_true', help='keep the temporary directory')
    ap.add_argument('--port-base', type=int, default=28500)
    ap.add_argument('--json', help='write the difference table here')
    args = ap.parse_args(argv)
    if not args.zakurad:
        ap.error('--zakurad (or KOGANY_BIN) is required')
    try:
        report, workdir = run(args)
    except RpcError as e:
        print('rpc_ycash_parity: %s' % e, file=sys.stderr)
        return 2
    report.print()
    for method, why in WALLET_ONLY.items():
        print('not compared: %-12s %s' % (method, why))
    if args.json:
        with open(args.json, 'w') as f:
            json.dump([dict(zip(('method', 'call', 'field', 'kind', 'ycash6', 'kogany', 'class', 'reason'), r))
                       for r in report.rows], f, indent=1, sort_keys=True)
    return 1 if report.failures() else 0


if __name__ == '__main__':
    sys.exit(main())
