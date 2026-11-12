#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""The stock-RPC contract cases of plan W7-c, checked against kogany and, with --ycash6-bin, against ycashd.

    python crates/kogany-rpc/qa/rpc_stock_contract.py --koganyd <koganyd, the --features ycash build> \\
        [--ycash6-bin $WS/wt/.bin/ycash6-65cb4ae0f] [--blocks 12] [--workdir DIR]

The cases are the ycashd shapes of `doc/yellowback-rpc.md` and `src/rpc/{rawtransaction,misc,
blockchain}.cpp` at ycash6 65cb4ae0f that a wallet-less node serves (plan K-3):

  sendrawtransaction  the third parameter `allowyedburn` (H7) is accepted, positionally, as
                      ycashd takes it; without a Yellowback wallet it changes nothing, so a
                      transaction is judged exactly as without it (`TX decode failed` -22 here).
                      The `yed-burn-refused` check is the wallet's: yewd's, never kogany's.
  validateaddress     a plain-YEC post-quantum address (`rq…` on regtest, `tq…` on the testnets,
                      `sq…` on mainnet; D-Q-20) of a registered scheme: `isvalid`, `address`,
                      `scriptPubKey` (TX_PQPKH), `isscript` false, `pqscheme`, `pqschemename`, `pqkeyhash`; an
                      unregistered scheme, another network's version and the Yellowback `yb…`/
                      `yt…`/`yr…` forms answer `{"isvalid": false}` (N9).
  getblockchaininfo   `chain` is ycashd's network name (`regtest`, `test`); `testnetprofile` is
                      `fast`/`slow` on the testnets only; `chainwork` is the tip's total work as a
                      64-digit hex string, which grows by each block's work.

With --ycash6-bin, a ycashd started with -disablewallet (the node context) answers the same calls
on the same chain (ycashd mines the regtest blocks, kogany follows by submitblock; the testnet at
genesis) and
every answer must be equal, except `ismine`/`iswatchonly`, which ycashd adds from its wallet code
even with -disablewallet and yewd adds in front of kogany (class `wallet`).

Exit 0 when every case passes, 1 otherwise, 2 when a node cannot be started. Stdlib only.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

DEFAULT_YCASH6_BIN = os.path.join(os.getenv('WS', ''), 'wt', '.bin', 'ycash6-65cb4ae0f')
# ycash6 qa/rpc-tests/test_framework/util.py: every upgrade through Canopy at height 1.
NUPARAMS = ['5ba81b19', '76b809bb', '374d694f', '8e471bd6', '66314da3', '19bd2d2f']
ACTIVATION_KEYS = ['Overwinter', 'Sapling', 'Ycash', 'Blossom', 'Heartwood', 'Canopy']
# zakura-rpc config/mining.rs: the Ycash regtest default miner address (W7-c).
MINER = 'smNJv8yYiY2tiqGdSvtrdMt6Rib5HwQ7Xr5'
# Fields ycashd's validateaddress adds from its wallet code even with -disablewallet (misc.cpp).
WALLET_FIELDS = {'ismine', 'iswatchonly'}

B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58check(payload):
    """ycashd's EncodeBase58Check of version || body."""
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, 'big')
    out = ''
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + out


class SetupError(Exception):
    pass


class Node:
    def __init__(self, name, port, auth=None):
        self.name, self.url, self.auth = name, 'http://127.0.0.1:%d/' % port, auth

    def call(self, method, *params):
        """(result, error) of one call."""
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
        headers = {'content-type': 'application/json'}
        if self.auth:
            import base64
            headers['authorization'] = 'Basic ' + base64.b64encode(self.auth.encode()).decode()
        req = urllib.request.Request(self.url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                answer = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            answer = json.loads(e.read() or b'{}')
        return answer.get('result'), answer.get('error')

    def ok(self, method, *params):
        result, error = self.call(method, *params)
        if error:
            raise SetupError('%s: %s%r: %s' % (self.name, method, params, error))
        return result


def free_ports(n):
    socks = []
    try:
        for _ in range(n):
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def zakurad_toml(root, p2p, rpc, v2, network):
    if network == 'regtest':
        net = '[network.network]\nregtest = true\n\n[network.network.params.activation_heights]\n' + \
              '\n'.join('%s = 1' % k for k in ACTIVATION_KEYS) + '\n'
        top = ''
    else:
        net, top = '', 'network = "Testnet"\n'
    return '''[network]
{top}listen_addr = "127.0.0.1:{p2p}"
initial_mainnet_peers = []
initial_testnet_peers = []
p2p_stack = "legacy"
cache_dir = "{root}/network"
identity_dir = "{root}/identity"

{net}
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
'''.format(top=top, p2p=p2p, rpc=rpc, v2=v2, root=root, net=net, miner=MINER)


def start_zakurad(binary, root, network):
    os.makedirs(root, exist_ok=True)
    p2p, rpc, v2 = free_ports(3)
    conf = os.path.join(root, 'zakurad.toml')
    with open(conf, 'w') as f:
        f.write(zakurad_toml(root, p2p, rpc, v2, network))
    log = open(os.path.join(root, 'zakurad.log'), 'ab')
    return subprocess.Popen([binary, '-c', conf, 'start'], stdout=log, stderr=subprocess.STDOUT), Node('kogany', rpc)


def start_ycashd(bindir, root, network):
    os.makedirs(root, exist_ok=True)
    port, rpcport = free_ports(2)
    net = 'regtest=1\n' if network == 'regtest' else 'testnet=1\ntestnetprofile=fast\n'
    with open(os.path.join(root, 'ycash.conf'), 'w') as f:
        f.write(net + 'showmetrics=0\nrpcuser=u\nrpcpassword=p\nport=%d\nrpcport=%d\nlistenonion=0\n'
                % (port, rpcport))
    args = [os.path.join(bindir, 'ycashd'), '-datadir=' + root, '-disablewallet', '-discover=0',
            '-listen=0', '-dnsseed=0', '-connect=0', '-experimentalfeatures',
            '-i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025']
    if network == 'regtest':
        args += ['-nuparams=%s:1' % b for b in NUPARAMS]
        args += ['-minetolocalwallet=0', '-mineraddress=' + MINER]
    log = open(os.path.join(root, 'ycashd.out'), 'a')
    return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT), Node('ycash6', rpcport, 'u:p')


def wait_up(node, proc, timeout=180, method='getblockcount'):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SetupError('%s exited with %s' % (node.name, proc.returncode))
        try:
            result, error = node.call(method)
            if error is None:
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    raise SetupError('%s did not come up' % node.name)


def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(60)
        except subprocess.TimeoutExpired:
            proc.kill()


class Cases:
    def __init__(self):
        self.rows = []

    def check(self, case, ok, detail=''):
        self.rows.append((case, bool(ok), str(detail)[:300]))
        print('%-4s %s%s' % ('ok' if ok else 'FAIL', case, ('  -- ' + str(detail)[:300]) if detail and not ok else ''))

    def failed(self):
        return [r for r in self.rows if not r[1]]


def strip_wallet(answer):
    return {k: v for k, v in answer.items() if k not in WALLET_FIELDS} if isinstance(answer, dict) else answer


def pq_addresses():
    """(label, address, expected scheme or None) for regtest: the scheme-visible forms (D-9, one
    3-byte version per network and scheme) and the pre-D-9 form, which is no address."""
    key_hash = bytes(range(32))
    return [
        ('rqs… SLH-DSA-SHA2-128s', base58check(b'\x4c\x56\x55' + key_hash), 1),
        ('rqf… FN-DSA-512', base58check(b'\x4c\x54\xef' + key_hash), 2),
        ('rq… pre-D-9 form', base58check(b'\x4c\x51\x01' + key_hash), None),
        ('rq… pre-D-9 form, unregistered scheme 3', base58check(b'\x4c\x51\x03' + key_hash), None),
        ('tqs… (the testnets\')', base58check(b'\x4f\x66\x7f' + key_hash), None),
        ('sqf… (mainnet\'s)', base58check(b'\x4d\xdd\x04' + key_hash), None),
        ('yrs… YED post-quantum', base58check(b'\x57\x15\xaa' + key_hash), None),
        ('yr… YED key hash', base58check(b'\x20\x02' + key_hash[:20]), None),
        ('rqs… bad checksum', base58check(b'\x4c\x56\x55' + key_hash)[:-1] + '1', None),
    ], key_hash


def regtest_cases(args, cases, procs):
    z_proc, z = start_zakurad(args.zakurad, os.path.join(args.workdir, 'zakurad-regtest'), 'regtest')
    procs.append(z_proc)
    wait_up(z, z_proc)
    y = None
    if args.ycash6_bin:
        y_proc, y = start_ycashd(args.ycash6_bin, os.path.join(args.workdir, 'ycashd-regtest'), 'regtest')
        procs.append(y_proc)
        wait_up(y, y_proc)

    # getblockchaininfo at genesis and after --blocks blocks mined by kogany (fed to ycashd).
    def info_cases(label):
        info = z.ok('getblockchaininfo')
        cases.check('getblockchaininfo.chain = "regtest" (%s)' % label, info.get('chain') == 'regtest', info.get('chain'))
        cases.check('getblockchaininfo.testnetprofile absent on regtest (%s)' % label,
                    'testnetprofile' not in info, info.get('testnetprofile'))
        work = info.get('chainwork')
        cases.check('getblockchaininfo.chainwork is a 64-digit hex string (%s)' % label,
                    isinstance(work, str) and re.fullmatch('[0-9a-f]{64}', work or ''), repr(work))
        if y:
            yinfo = y.ok('getblockchaininfo')
            for field in ('chain', 'chainwork', 'blocks', 'bestblockhash'):
                cases.check('getblockchaininfo.%s = ycashd\'s (%s)' % (field, label),
                            info.get(field) == yinfo.get(field), '%r | %r' % (yinfo.get(field), info.get(field)))
            cases.check('getblockchaininfo.testnetprofile absent on ycashd regtest too (%s)' % label,
                        'testnetprofile' not in yinfo, yinfo.get('testnetprofile'))
        return info

    genesis = info_cases('genesis')
    if y:
        # kogany's regtest blocks carry no Equihash solution (Zakura disables proof of work on
        # Regtest), so ycashd mines and kogany follows, as in rpc_ycash_parity.py. kogany's own
        # template must still build with the Ycash miner address (finding F4).
        template, err = z.call('getblocktemplate')
        cases.check('getblocktemplate on a ycash regtest with a Ycash miner address', err is None and template, err)
        hashes = y.ok('generate', args.blocks)
        for h in hashes:
            res = z.ok('submitblock', y.ok('getblock', h, 0))
            if res is not None:
                raise SetupError('kogany refused ycashd block %s: %r' % (h, res))
        deadline = time.time() + 60
        while z.ok('getbestblockhash') != hashes[-1] and time.time() < deadline:
            time.sleep(0.5)
    else:
        hashes = z.ok('generate', args.blocks)
        cases.check('generate %d on a ycash regtest with the Ycash miner address' % args.blocks,
                    isinstance(hashes, list) and len(hashes) == args.blocks, hashes)
    tip = info_cases('height %d' % args.blocks)
    if genesis.get('chainwork') and tip.get('chainwork'):
        bits = z.ok('getblockheader', hashes[-1], True)['bits'] if hashes else None
        cases.check('chainwork grew with the chain', int(tip['chainwork'], 16) > int(genesis['chainwork'], 16),
                    '%s -> %s (bits %s)' % (genesis['chainwork'], tip['chainwork'], bits))

    # sendrawtransaction's allowyedburn (H7).
    for params in (['00'], ['00', False], ['00', False, True], ['00', True, False]):
        _, err = z.call('sendrawtransaction', *params)
        code = (err or {}).get('code')
        cases.check('sendrawtransaction%r is judged as a transaction (decode error -22), the flag accepted'
                    % (tuple(params),), code == -22, err)
        if y:
            _, yerr = y.call('sendrawtransaction', *params)
            cases.check('sendrawtransaction%r: ycashd -disablewallet answers the same code' % (tuple(params),),
                        (yerr or {}).get('code') == code, '%r | %r' % (yerr, err))

    # validateaddress of the post-quantum forms.
    addrs, key_hash = pq_addresses()
    for label, addr, scheme in addrs:
        answer = z.ok('validateaddress', addr)
        if scheme:
            want = {'isvalid': True, 'address': addr,
                    'scriptPubKey': '20%s%02xc2' % (key_hash.hex(), 0x50 + scheme),
                    'isscript': False, 'pqscheme': scheme,
                    'pqschemename': {1: 'SLH-DSA-SHA2-128s', 2: 'FN-DSA-512'}[scheme], 'pqkeyhash': key_hash.hex()}
        else:
            want = {'isvalid': False}
        cases.check('validateaddress %s' % label, answer == want, '%r, want %r' % (answer, want))
        if y:
            yanswer = y.ok('validateaddress', addr)
            cases.check('validateaddress %s = ycashd\'s (but ismine/iswatchonly)' % label,
                        strip_wallet(yanswer) == answer, '%r | %r' % (yanswer, answer))


def testnet_cases(args, cases, procs):
    """The default Ycash testnet (fast profile) at genesis. A testnet zakurad without peers has no
    genesis block (Regtest commits its own), so ycashd's is fed to it: these cases need ycashd."""
    y_proc, y = start_ycashd(args.ycash6_bin, os.path.join(args.workdir, 'ycashd-testnet'), 'testnet')
    procs.append(y_proc)
    wait_up(y, y_proc)
    z_proc, z = start_zakurad(args.zakurad, os.path.join(args.workdir, 'zakurad-testnet'), 'testnet')
    procs.append(z_proc)
    wait_up(z, z_proc, method='getinfo')
    genesis = y.ok('getblockhash', 0)
    res = z.ok('submitblock', y.ok('getblock', genesis, 0))
    deadline = time.time() + 60
    while z.call('getbestblockhash')[0] != genesis and time.time() < deadline:
        time.sleep(0.5)
    if res is not None or z.call('getbestblockhash')[0] != genesis:
        raise SetupError('kogany did not take the testnet genesis block: %r' % (res,))
    info, yinfo = z.ok('getblockchaininfo'), y.ok('getblockchaininfo')
    cases.check('getblockchaininfo.chain = "test" (testnet, fast profile)', info.get('chain') == 'test', info.get('chain'))
    cases.check('getblockchaininfo.testnetprofile = "fast" (the default Ycash testnet)',
                info.get('testnetprofile') == 'fast', info.get('testnetprofile'))
    for field in ('chain', 'testnetprofile', 'chainwork', 'bestblockhash'):
        cases.check('getblockchaininfo.%s = ycashd -testnet -testnetprofile=fast\'s (genesis)' % field,
                    info.get(field) == yinfo.get(field), '%r | %r' % (yinfo.get(field), info.get(field)))
    addrs, _ = pq_addresses()
    for label, addr, _scheme in addrs:
        answer, yanswer = z.ok('validateaddress', addr), y.ok('validateaddress', addr)
        cases.check('validateaddress %s on the testnet = ycashd\'s (but ismine/iswatchonly)' % label,
                    strip_wallet(yanswer) == answer, '%r | %r' % (yanswer, answer))
        if label.startswith('tqs'):
            cases.check('validateaddress tqs… is valid on the testnet',
                        answer.get('isvalid') is True and answer.get('pqscheme') == 1, answer)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--koganyd', '--zakurad', dest='zakurad', default=os.getenv('KOGANY_BIN'),
                    help='koganyd (the --features ycash build; --zakurad is its old name)')
    ap.add_argument('--ycash6-bin', help='directory holding ycashd: compare with it (e.g. %s)' % DEFAULT_YCASH6_BIN)
    ap.add_argument('--blocks', type=int, default=12)
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--no-testnet', action='store_true', help='skip the testnet cases (they need --ycash6-bin)')
    args = ap.parse_args(argv)
    if not args.zakurad:
        ap.error('--koganyd (or KOGANY_BIN) is required')
    temp = not args.workdir
    args.workdir = os.path.abspath(args.workdir or tempfile.mkdtemp(prefix='rpc-stock-contract-'))
    cases, procs = Cases(), []
    try:
        regtest_cases(args, cases, procs)
        if args.ycash6_bin and not args.no_testnet:
            testnet_cases(args, cases, procs)
    except SetupError as e:
        print('rpc_stock_contract: %s (logs in %s)' % (e, args.workdir), file=sys.stderr)
        return 2
    finally:
        for p in reversed(procs):
            stop(p)
        if temp and not cases.failed():
            shutil.rmtree(args.workdir, ignore_errors=True)
    failed = cases.failed()
    print('%d of %d contract cases pass' % (len(cases.rows) - len(failed), len(cases.rows)))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
