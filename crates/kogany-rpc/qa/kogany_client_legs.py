#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""The lightwalletd-dd and chain-viz client legs against a regtest kogany (plan W7-d; report-only).

    python crates/kogany-rpc/qa/kogany_client_legs.py \\
        --zakurad target/debug/zakurad --lightwalletd BIN --lwdinfo BIN --chain-viz BIN \\
        [--miner-address ADDR] [--blocks 25] [--out DIR] [--port-base N] [--strict]

It starts one regtest `zakurad` per scenario and runs each client against it, unmodified, through
its public interface only:

  mock      KOGANY_VAULT_RPC_MOCK=1 KOGANY_YED_RPC_MOCK=1: the vault and yed_* reads answer from
            kogany-rpc's fixtures (plan W7-a/W7-b), Yellowback is "live".
  not-live  KOGANY_VAULT_RPC_MOCK=1 only: every yed_* method answers -32601 "Yellowback is not
            active", zakurad's default until plan W5-f registers the module.

lightwalletd-dd (`--yellowback`): its startup probe (`common/yellowback.go` ProbeYellowback) must
start the YellowbackStreamer service on `mock` (rpcversion 8) and not on `not-live`; its own probe
tool `testtools/lwdinfo -yellowback` must answer GetLightdInfo at the node's height and, on
`mock`, every Yellowback method "ok" except the four whose harmless inputs the node refuses
(GetTxInfo, GetVault, GetNotice: an unknown txid; ValidateRawTransaction: not a transaction),
which must carry the node's own error as FailedPrecondition; on `not-live` every method is
Unimplemented, as against the baseline server.

chain-viz (polling: kogany has no ZMQ and no -blocknotify, plan K-17): `/api/health` must be
`ok` with the node up and its tip equal to the node's best block; `/api/snapshot` must show the
node's Yellowback flag as the scenario says (true on `mock`, false on `not-live`) and its vault
panel available, with no node error.

Mining: with `--miner-address`, `generate --blocks` first, so the clients see a chain; when the
node refuses (a `ycash` build before plan W8 builds Ycash coinbases) the refusal is recorded and
the legs run at genesis. The report (`--out`/client-legs.json and .md, and stdout) lists every
check as pass or fail. Exit 0 whatever the checks say (the legs are report-only, plan §5) unless
`--strict`; exit 2 when a process cannot be started. Stdlib only.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

SCENARIOS = {
    'mock': {'KOGANY_VAULT_RPC_MOCK': '1', 'KOGANY_YED_RPC_MOCK': '1'},
    'not-live': {'KOGANY_VAULT_RPC_MOCK': '1'},
}
# lwdinfo's harmless inputs that the node refuses (testtools/lwdinfo/main.go probeYellowback)
REFUSED_INPUTS = {
    'GetTxInfo': 'tx-not-found',
    'GetVault': 'vault-not-found',
    'GetNotice': 'vault-not-found',
    'ValidateRawTransaction': 'TX decode failed',
}
LWD_STARTED = 'Yellowback service started (node rpcversion 8'
LWD_NOT_STARTED = 'Yellowback service not started: the node has no yed_* commands'


class SetupError(Exception):
    pass


def rpc(url, method, params=(), timeout=60):
    body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)}).encode()
    req = urllib.request.Request(url, data=body, headers={'content-type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            answer = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        answer = json.loads(e.read() or b'{}')
    if answer.get('error'):
        raise RuntimeError('%s: %s' % (method, answer['error'].get('message')))
    return answer.get('result')


def http_json(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read())


def zakurad_toml(datadir, ports, miner_address):
    """A regtest zakurad.toml (the harness's form, ycash6 qa/rpc-tests/test_framework/kogany.py)."""
    lines = [
        '[network]',
        'listen_addr = "127.0.0.1:%d"' % ports['p2p'],
        'initial_testnet_peers = []',
        'p2p_stack = "legacy"',
        'cache_dir = "%s"' % os.path.join(datadir, 'network'),
        'identity_dir = "%s"' % os.path.join(datadir, 'identity'),
        '[network.network]',
        'regtest = true',
        '[network.network.params]',
        'activation_heights = { Overwinter = 1, Sapling = 1, Blossom = 1, Heartwood = 1, Canopy = 1 }',
        '[network.zakura]',
        'listen_addr = "127.0.0.1:%d"' % ports['v2'],
        '[rpc]',
        'listen_addr = "127.0.0.1:%d"' % ports['rpc'],
        'enable_cookie_auth = false',
        'cookie_dir = "%s"' % os.path.join(datadir, 'rpc'),
        '[state]',
        'cache_dir = "%s"' % os.path.join(datadir, 'state'),
        'ephemeral = false',
        '[mempool]',
        'debug_enable_at_height = 0',
        '[mining]',
        'internal_miner = false',
    ]
    if miner_address:
        lines.append('miner_address = "%s"' % miner_address)
    lines += ['[tracing]', 'use_color = false', 'filter = "info"']
    return '\n'.join(lines) + '\n'


class Procs:
    """The scenario's child processes, stopped in reverse order."""

    def __init__(self):
        self.procs = []

    def start(self, name, argv, log, env=None, cwd=None):
        out = open(log, 'ab')
        p = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env, cwd=cwd)
        self.procs.append((name, p))
        return p

    def stop(self):
        for _name, p in reversed(self.procs):
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        for _name, p in reversed(self.procs):
            try:
                p.wait(20)
            except subprocess.TimeoutExpired:
                p.kill()
        self.procs = []


def wait_for(predicate, timeout, step=0.5):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as e:  # noqa: BLE001 - polled until the deadline
            last = e
        time.sleep(step)
    if last is not None:
        raise SetupError(str(last))
    return None


class Report:
    def __init__(self):
        self.rows = []
        self.notes = []

    def check(self, scenario, leg, name, ok, detail=''):
        self.rows.append({'scenario': scenario, 'leg': leg, 'check': name, 'pass': bool(ok), 'detail': str(detail)[:400]})

    def note(self, scenario, text):
        self.notes.append({'scenario': scenario, 'note': text})

    def markdown(self):
        out = ['# kogany client legs (report-only, plan W7-d)', '',
               '| scenario | leg | check | result | detail |', '|---|---|---|---|---|']
        for r in self.rows:
            out.append('| %s | %s | %s | %s | %s |' % (r['scenario'], r['leg'], r['check'],
                                                   'pass' if r['pass'] else '**fail**',
                                                   r['detail'].replace('|', '\\|').replace('\n', ' ')))
        if self.notes:
            out += ['', 'Notes:', '']
            out += ['- %s: %s' % (n['scenario'], n['note']) for n in self.notes]
        passed = sum(r['pass'] for r in self.rows)
        out += ['', '%d of %d checks pass.' % (passed, len(self.rows))]
        return '\n'.join(out) + '\n'


def lightwalletd_leg(args, scenario, work, ports, height, procs, report):
    datadir = os.path.join(work, 'lightwalletd')
    os.makedirs(datadir, exist_ok=True)
    log = os.path.join(work, 'lightwalletd.log')
    procs.start('lightwalletd', [
        args.lightwalletd, '--rpcuser', 'kogany', '--rpcpassword', 'kogany', '--rpchost', '127.0.0.1',
        '--rpcport', str(ports['rpc']), '--no-tls-very-insecure',
        '--grpc-bind-addr', '127.0.0.1:%d' % ports['lwd'], '--http-bind-addr', '127.0.0.1:%d' % ports['lwdhttp'],
        '--data-dir', datadir, '--log-file', log, '--yellowback'], os.path.join(work, 'lightwalletd.out'))
    want = LWD_STARTED if scenario == 'mock' else LWD_NOT_STARTED

    def probe_logged():
        with open(log, encoding='utf-8', errors='replace') as f:
            text = f.read()
        return (LWD_STARTED in text or 'Yellowback service not started' in text) and text
    text = wait_for(probe_logged, 30) or ''
    line = next((ln for ln in text.splitlines() if 'Yellowback service' in ln), 'no Yellowback line in the log')
    report.check(scenario, 'lightwalletd-dd', 'startup probe: ' + ('service started, rpcversion 8' if scenario == 'mock' else 'service not started (-32601)'),
                 want in text, json.loads(line).get('msg', line) if line.startswith('{') else line)

    out = subprocess.run([args.lwdinfo, '-server', '127.0.0.1:%d' % ports['lwd'], '-timeout', '10s', '-yellowback'],
                         capture_output=True, text=True, timeout=120)
    report.check(scenario, 'lightwalletd-dd', 'lwdinfo exits 0', out.returncode == 0, out.stderr.strip()[-300:])
    if out.returncode != 0:
        return
    info = json.loads(out.stdout)
    report.check(scenario, 'lightwalletd-dd', 'GetLightdInfo.blockHeight = node height', info.get('blockHeight') == height,
                 'blockHeight %s, node %s, chainName %s, branch %s' % (info.get('blockHeight'), height, info.get('chainName'), info.get('consensusBranchId')))
    yb = info.get('yellowback', {})
    methods = sorted(k for k in yb if '#' not in k)
    if scenario == 'mock':
        bad = []
        for m in methods:
            v = yb[m]
            if m in REFUSED_INPUTS:
                if not (v.startswith('FailedPrecondition') and REFUSED_INPUTS[m] in v):
                    bad.append('%s: %s' % (m, v))
            elif v != 'ok':
                bad.append('%s: %s' % (m, v))
        report.check(scenario, 'lightwalletd-dd', 'every YellowbackStreamer method answers (%d methods)' % len(methods),
                     methods and not bad, '; '.join(bad) or 'rpcversion %s, upgrade %s' % (
                         yb.get('GetYellowbackInfo#rpcversion'), yb.get('GetYellowbackInfo#upgrade')))
    else:
        bad = ['%s: %s' % (m, yb[m]) for m in methods if not yb[m].startswith('Unimplemented')]
        report.check(scenario, 'lightwalletd-dd', 'every YellowbackStreamer method Unimplemented (%d methods)' % len(methods),
                     methods and not bad, '; '.join(bad))


def chain_viz_leg(args, scenario, work, ports, best, procs, report):
    base = 'http://127.0.0.1:%d' % ports['cv']
    procs.start('chain-viz', [args.chain_viz, '--nodes', 'http://kogany:kogany@127.0.0.1:%d' % ports['rpc'],
                              '--listen', '127.0.0.1:%d' % ports['cv'], '--poll', '1'],
                os.path.join(work, 'chain-viz.log'))

    def settled():
        h = http_json(base + '/api/health')
        return h if (h.get('tip') or {}).get('hash') == best['hash'] and h.get('nodesUp') == 1 else None
    try:
        wait_for(settled, 30)
    except SetupError:
        pass
    try:
        health = http_json(base + '/api/health')
        snap = http_json(base + '/api/snapshot')
    except Exception as e:  # noqa: BLE001
        report.check(scenario, 'chain-viz', 'API answers', False, e)
        return
    node = (snap.get('nodes') or [{}])[0]
    calls = (health.get('rpcCalls') or {}).get('0', {})
    report.check(scenario, 'chain-viz', 'health ok, node up', health.get('ok') and health.get('nodesUp') == 1,
                 'ok %s, nodesUp %s, node error %r' % (health.get('ok'), health.get('nodesUp'), node.get('error')))
    tip = health.get('tip') or {}
    report.check(scenario, 'chain-viz', 'tip = node best block', tip.get('hash') == best['hash'] and tip.get('height') == best['height'],
                 'tip %s, node %s' % (tip, best))
    report.check(scenario, 'chain-viz', 'Yellowback flag %s' % ('true' if scenario == 'mock' else 'false'),
                 node.get('yellowback') is (scenario == 'mock'), 'nodes[0].yellowback = %r' % node.get('yellowback'))
    vault = snap.get('vault') or {}
    report.check(scenario, 'chain-viz', 'vault panel available', node.get('vault') is True and vault.get('available') is True,
                 'nodes[0].vault %r, vault.available %r, sets %s' % (node.get('vault'), vault.get('available'), (vault.get('info') or {}).get('sets')))
    report.check(scenario, 'chain-viz', 'no node error', not node.get('error'), node.get('error') or '')
    report.note(scenario, 'chain-viz RPC calls: ' + ', '.join('%s %d' % kv for kv in sorted(calls.items())))


def free_ports(names):
    """One free loopback port per name (held open together, so they differ)."""
    socks = []
    try:
        for _ in names:
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            socks.append(s)
        return {name: s.getsockname()[1] for name, s in zip(names, socks)}
    finally:
        for s in socks:
            s.close()


def run_scenario(args, scenario, port_base, report):
    names = ('rpc', 'p2p', 'v2', 'lwd', 'lwdhttp', 'cv')
    ports = {k: port_base + i for i, k in enumerate(names)} if port_base else free_ports(names)
    work = os.path.join(args.out, scenario)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    conf = os.path.join(work, 'zakurad.toml')
    with open(conf, 'w', encoding='utf-8') as f:
        f.write(zakurad_toml(work, ports, args.miner_address))
    env = dict(os.environ)
    for k in ('KOGANY_VAULT_RPC_MOCK', 'KOGANY_YED_RPC_MOCK'):
        env.pop(k, None)
    env.update(SCENARIOS[scenario])
    url = 'http://127.0.0.1:%d/' % ports['rpc']
    procs = Procs()
    try:
        z = procs.start('zakurad', [args.zakurad, '-c', conf, 'start'], os.path.join(work, 'zakurad.log'), env=env)

        def up():
            if z.poll() is not None:
                raise SetupError('zakurad exited with %s; see %s' % (z.returncode, os.path.join(work, 'zakurad.log')))
            return rpc(url, 'getblockcount', timeout=5) is not None
        if not wait_for(up, 120):
            raise SetupError('zakurad RPC did not come up')
        if args.miner_address and args.blocks:
            try:
                rpc(url, 'generate', [args.blocks], timeout=600)
            except RuntimeError as e:
                report.note(scenario, 'mining refused, legs run at genesis: %s' % e)
        else:
            report.note(scenario, 'no --miner-address: legs run at genesis')
        height = rpc(url, 'getblockcount')
        best = {'hash': rpc(url, 'getbestblockhash'), 'height': height}
        chain = rpc(url, 'getblockchaininfo')
        report.note(scenario, 'zakurad at height %d, chain %s, getblockchaininfo.chainwork %r' % (
            height, chain.get('chain'), chain.get('chainwork')))
        if args.lightwalletd:
            lightwalletd_leg(args, scenario, work, ports, height, procs, report)
        if args.chain_viz:
            chain_viz_leg(args, scenario, work, ports, best, procs, report)
    finally:
        procs.stop()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--zakurad', required=True)
    ap.add_argument('--lightwalletd', help='lightwalletd-dd binary (omit to skip the leg)')
    ap.add_argument('--lwdinfo', help="lightwalletd-dd's testtools/lwdinfo binary")
    ap.add_argument('--chain-viz', help='chain-viz binary (omit to skip the leg)')
    ap.add_argument('--miner-address', help='mine --blocks to this address first (a regtest transparent address)')
    ap.add_argument('--blocks', type=int, default=25)
    ap.add_argument('--scenario', choices=sorted(SCENARIOS), action='append', help='default: both')
    ap.add_argument('--out', help='work and report directory (default: a temporary directory)')
    ap.add_argument('--port-base', type=int, default=0, help='fixed ports from N (default: free ports)')
    ap.add_argument('--strict', action='store_true', help='exit 1 when a check fails')
    args = ap.parse_args(argv)
    if args.lightwalletd and not args.lwdinfo:
        ap.error('--lightwalletd needs --lwdinfo')
    args.out = os.path.abspath(args.out or tempfile.mkdtemp(prefix='kogany-client-legs-'))
    os.makedirs(args.out, exist_ok=True)
    report = Report()
    status = 0
    for i, scenario in enumerate(args.scenario or ['mock', 'not-live']):
        try:
            run_scenario(args, scenario, args.port_base and args.port_base + 10 * i, report)
        except SetupError as e:
            report.note(scenario, 'setup failed: %s' % e)
            status = 2
    md = report.markdown()
    with open(os.path.join(args.out, 'client-legs.json'), 'w', encoding='utf-8') as f:
        json.dump({'checks': report.rows, 'notes': report.notes}, f, indent=2)
    with open(os.path.join(args.out, 'client-legs.md'), 'w', encoding='utf-8') as f:
        f.write(md)
    sys.stdout.write(md)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write(md)
    if status:
        return status
    if args.strict and not all(r['pass'] for r in report.rows):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
