#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""A live Yellowback regtest for kogany's yed_* reads (plan W7-b, W9-c): kogany and a ycash6 sidecar
on one chain with a real attestor set, three seated attestors, an armed attestation layer, a
quoting pool and a mint.

    python crates/kogany-rpc/qa/yed_live_rig.py --zakurad Z --ycashd Y --ycash6 TREE --dir D [--keep]

kogany is wallet-less (plan K-3), so the sidecar (`ycashd`, `connect=` kogany) holds the wallet and
mines. The YED attestor set must exist before Yellowback starts (U-22): the sidecar first runs
alone without one, mines to the Vault activation, creates the set (`set_create`, ycash6's
`ATTESTOR_SET_SPEC`) and mines it; then kogany starts with `[yellowback] attestor_set` = that set
and syncs the chain from the restarted sidecar (`-yellowbackattestorset`,
`-yellowbackpayoutaddress`). The sidecar quotes (`yed_setquote`), registers attestors 0..2 (ycash6's
`register_and_arm` keys and `build_register_tx`), mines until the layer is ARMED and the price
windows are full, feeds the attestations of R = tip - REF_LAG to both nodes, and mints
(`yed_mint`, the two-step carrier flow).

ycash6's test framework (`qa/rpc-tests/test_framework`, the tree `--ycash6` names) builds the
registrations and signs the attestations; it is imported unmodified. `LiveRig` is also the
library the client-leg and contract runners use (`live_rig.up()`, `.mine(n)`, `.feed()`, `.down()`).
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

NUPARAMS = ['5ba81b19', '76b809bb', '374d694f', '8e471bd6', '66314da3', '19bd2d2f']
ACTIVATION_KEYS = ['Overwinter', 'Sapling', 'Ycash', 'Blossom', 'Heartwood', 'Canopy']
VAULT_BRANCH = '6d5b7a31'
VAULT = 110
QUOTE = 100_000_000           # $100/YEC: a $100 mint locks a few YEC of the regtest coinbases
MINT_CENTS = 10_000


class RigError(Exception):
    pass


class Rpc:
    """A JSON-RPC client: `node.method(*params)`; errors raise RigError(code, message)."""

    def __init__(self, url, user=None, password=None):
        self.url, self.user, self.password = url, user, password

    def call(self, method, *params, timeout=300):
        import base64
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        req = urllib.request.Request(self.url, data=body, headers={'content-type': 'application/json'})
        if self.user is not None:
            req.add_header('Authorization', 'Basic ' + base64.b64encode(('%s:%s' % (self.user, self.password)).encode()).decode())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                answer = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            answer = json.loads(e.read() or b'{}')
        if answer.get('error'):
            raise RigError(answer['error'].get('code'), answer['error'].get('message'))
        return answer.get('result')

    def __getattr__(self, method):
        if method.startswith('_'):
            raise AttributeError(method)
        return lambda *params: self.call(method, *params)


def free_ports(n):
    socks, ports = [], []
    for _ in range(n):
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        socks.append(s)
        ports.append(s.getsockname()[1])
    for s in socks:
        s.close()
    return ports


def wait_for(what, predicate, timeout=300, step=0.5):
    deadline = time.time() + timeout
    while True:
        try:
            if predicate():
                return
        except (RigError, OSError, urllib.error.URLError, ConnectionError):
            pass
        if time.time() > deadline:
            raise RigError(-1, 'timed out waiting for %s' % what)
        time.sleep(step)


def zakurad_toml(root, ports, attestor_set, miner_address):
    heights = '\n'.join(['%s = 1' % k for k in ACTIVATION_KEYS] + ['Vault = %d' % VAULT])
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

[yellowback]
attestor_set = "{attestor_set}"

[tracing]
use_color = false
filter = "info"
'''.format(root=root, heights=heights, attestor_set=attestor_set, miner=miner_address, **ports)


class LiveRig:
    """kogany + a ycash6 sidecar with a live, armed Yellowback and one mint."""

    def __init__(self, zakurad, ycashd, ycash6, workdir):
        self.zakurad, self.ycashd, self.ycash6 = os.path.abspath(zakurad), os.path.abspath(ycashd), ycash6
        self.dir = os.path.abspath(workdir)
        self.procs = {}
        p2p, v2, rpc, yp2p, yrpc = free_ports(5)
        self.ports = {'p2p': p2p, 'v2': v2, 'rpc': rpc, 'yp2p': yp2p, 'yrpc': yrpc}
        self.kogany = Rpc('http://127.0.0.1:%d/' % rpc)
        self.sidecar = Rpc('http://127.0.0.1:%d/' % yrpc, 'rig', 'rig')
        self.setid = None
        self.mint = None
        self._framework = None

    # -- ycash6's test framework (registrations, attestation signatures) --

    def framework(self):
        if self._framework is None:
            sys.path.insert(0, os.path.join(self.ycash6, 'qa', 'rpc-tests'))
            import test_framework.yellowback_attest as ya
            import test_framework.yellowback_util as yu
            self._framework = (yu, ya)
        return self._framework

    # -- processes --

    def _spawn(self, name, argv):
        log = open(os.path.join(self.dir, name + '.log'), 'ab')
        self.procs[name] = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        return self.procs[name]

    def _ycashd_args(self, extra):
        ydir = os.path.join(self.dir, 'ycashd')
        return ([self.ycashd, '-datadir=' + ydir, '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
                + ['-nuparams=%s:1' % b for b in NUPARAMS] + ['-nuparams=%s:%d' % (VAULT_BRANCH, VAULT)] + extra)

    def _start_sidecar(self, extra, connect):
        ydir = os.path.join(self.dir, 'ycashd')
        os.makedirs(ydir, exist_ok=True)
        with open(os.path.join(ydir, 'ycash.conf'), 'w', encoding='utf-8') as f:
            f.write('regtest=1\nserver=1\nshowmetrics=0\nprinttoconsole=0\nrpcuser=rig\nrpcpassword=rig\n'
                    'rpcallowip=127.0.0.1\nlistenonion=0\ndiscover=0\ndnsseed=0\ntxindex=1\n'
                    'experimentalfeatures=1\ninsightexplorer=1\nport=%d\nrpcport=%d\n' % (self.ports['yp2p'], self.ports['yrpc']))
            if connect:
                f.write('listen=0\nconnect=127.0.0.1:%d\n' % self.ports['p2p'])
            else:
                f.write('listen=0\nconnect=0\n')
        p = self._spawn('ycashd', self._ycashd_args(extra))

        def up():
            if p.poll() is not None:
                raise RigError(-1, 'ycashd exited with %s; see %s' % (p.returncode, os.path.join(self.dir, 'ycashd.log')))
            return isinstance(self.sidecar.getblockcount(), int)
        wait_for('the sidecar RPC', up, 300)

    def _stop_sidecar(self):
        try:
            self.sidecar.stop()
        except (RigError, OSError, urllib.error.URLError):
            pass
        p = self.procs.pop('ycashd', None)
        if p is not None:
            try:
                p.wait(120)
            except subprocess.TimeoutExpired:
                p.kill()

    def _start_kogany(self):
        root = os.path.join(self.dir, 'zakurad')
        os.makedirs(root, exist_ok=True)
        conf = os.path.join(self.dir, 'zakurad.toml')
        with open(conf, 'w', encoding='utf-8') as f:
            f.write(zakurad_toml(root, self.ports, self.setid, self.payout))
        env = dict(os.environ)
        for k in ('KOGANY_VAULT_RPC_MOCK', 'KOGANY_YED_RPC_MOCK'):
            env.pop(k, None)
        log = open(os.path.join(self.dir, 'zakurad.log'), 'ab')
        self.procs['zakurad'] = p = subprocess.Popen([self.zakurad, '-c', conf, 'start'], stdout=log, stderr=subprocess.STDOUT,
                                                     env=env, start_new_session=True)

        def up():
            if p.poll() is not None:
                raise RigError(-1, 'zakurad exited with %s; see %s' % (p.returncode, os.path.join(self.dir, 'zakurad.log')))
            return isinstance(self.kogany.getblockcount(), int)
        wait_for('the kogany RPC', up, 180)

    def down(self):
        self._stop_sidecar()
        for name, p in list(self.procs.items()):
            try:
                os.killpg(p.pid, signal.SIGTERM)
                p.wait(60)
            except (ProcessLookupError, subprocess.TimeoutExpired, PermissionError):
                p.kill()
        self.procs.clear()

    # -- the chain --

    def synced(self):
        tip = self.sidecar.getbestblockhash()
        wait_for('kogany at the sidecar tip %s' % tip, lambda: self.kogany.getbestblockhash() == tip, 180)

    def mine(self, n=1):
        self.sidecar.generate(n)
        self.synced()
        return self.sidecar.getblockcount()

    def up(self):
        """The two-phase start of U-22 (see the module doc); the chain then has the set at
        VAULT + 1."""
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        yu, _ya = self.framework()
        self._start_sidecar([], connect=False)
        self.sidecar.generate(VAULT)
        # set_create spends no coinbase: give the wallet ordinary coins first
        fund = self.sidecar.getnewaddress()
        for _ in range(4):
            self.sidecar.sendtoaddress(fund, 10)
        self.sidecar.generate(1)
        self.setid = self.sidecar.set_create(dict(yu.ATTESTOR_SET_SPEC))['setid']
        self.sidecar.generate(1)
        self.payout = self.sidecar.getnewaddress()
        self._stop_sidecar()
        self._start_kogany()
        self._start_sidecar(['-yellowbackattestorset=' + self.setid, '-yellowbackpayoutaddress=' + self.payout], connect=True)
        wait_for('the sidecar connected to kogany', lambda: self.sidecar.getpeerinfo(), 120)
        self.synced()
        yu.ATTESTOR_SET[0] = self.setid
        return self

    def arm(self):
        """Quote, register attestors 0..2 (one block), mine until ARMED with a defined pMint at
        tip - REF_LAG."""
        yu, ya = self.framework()
        self.sidecar.yed_setquote(QUOTE, 1)
        hot, bond = ya.attestor_keys(yu.ATTEST_ARM_MIN), ya.bond_keys(yu.ATTEST_ARM_MIN)
        for i in range(yu.ATTEST_ARM_MIN):
            raw, _lt = ya.build_register_tx(self.sidecar, hot[i][1], bond[i][1], yu.BOND_MIN_ZAT, yu.BOND_MIN_LOCK)
            ya.send_and_lock(self.sidecar, raw)
        self.mine(1)
        for _ in range(200):
            info = self.sidecar.yed_getinfo()
            ref = info['height'] - info['params']['refLag']
            armed = (info.get('attest') or {}).get('armed')
            if armed and self.sidecar.yed_getprice(ref).get('pMint'):
                return info
            self.mine(1)
        raise RigError(-1, 'the attestation layer never armed with a price')

    def feed(self, cited=None):
        """Every registered attestor signs pMint at `cited` (default tip - REF_LAG), pooled on both
        nodes. Returns the attestation hexes."""
        yu, ya = self.framework()
        if cited is None:
            cited = self.sidecar.getblockcount() - yu.REF_LAG
        price = int(self.sidecar.yed_getprice(cited)['pMint'])
        blockhash = self.sidecar.getblockhash(cited)
        out = []
        for rec in self.sidecar.yed_listattestors():
            seq = int(rec['seq'])
            att = ya.sign_attestation(ya.hot_secret_for(self.sidecar, seq), seq, price, cited, blockhash).hex()
            for node in (self.sidecar, self.kogany):
                node.yed_addattestation(att)
            out.append(att)
        return out

    def do_mint(self, lock_blocks):
        """`yed_mint` on the sidecar (two-step: the carrier, then the mint) while mining."""
        self.feed()
        box = {}

        def run():
            try:
                box['result'] = self.sidecar.call('yed_mint', MINT_CENTS, lock_blocks, '', '', True, timeout=900)
            except Exception as e:  # noqa: BLE001 -- reported below
                box['error'] = e
        t = threading.Thread(target=run)
        t.start()
        while t.is_alive():
            t.join(3)
            if t.is_alive():
                self.mine(1)
                self.feed()
        if 'error' in box:
            raise box['error']
        self.mine(1)
        self.mint = box['result']
        return self.mint


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--zakurad', required=True)
    ap.add_argument('--ycashd', required=True)
    ap.add_argument('--ycash6', required=True, help='a ycash6 tree (its qa/rpc-tests test framework)')
    ap.add_argument('--dir', required=True)
    ap.add_argument('--keep', action='store_true', help='leave both nodes running')
    args = ap.parse_args(argv)
    rig = LiveRig(args.zakurad, args.ycashd, args.ycash6, args.dir)
    try:
        rig.up()
        info = rig.arm()
        lock = info['params']['classes'][0]['minBlocks']
        rig.do_mint(lock)
        print(json.dumps({'dir': rig.dir, 'kogany': rig.kogany.url, 'sidecar': rig.sidecar.url, 'setid': rig.setid,
                          'height': rig.kogany.getblockcount(), 'mint': rig.mint}, indent=2, default=str))
    finally:
        if not args.keep:
            rig.down()
    return 0


if __name__ == '__main__':
    sys.exit(main())
