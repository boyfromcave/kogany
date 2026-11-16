#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""kogany's reorganisation guard against ycashd's, on one Ycash regtest chain (beta3 item 12, R1).

    python crates/kogany-rpc/qa/reorg_parity.py --koganyd <koganyd, the --features ycash build> \\
        [--ycash6-bin $WS/wt/.bin/ycash6-65cb4ae0f] [--workdir DIR] [--keep] [--depths 99,100,101]
        [--invalidate-depths 99,100]

ycashd refuses a reorganisation that rolls back more than 99 blocks (`MAX_REORG_LENGTH`, ycash6
`src/main.h:69`): it logs "A block chain reorganization has been detected that would roll back
<d> blocks! ..." and shuts down on its old tip (`src/main.cpp:5004-5022`). koganyd built with the
`ycash` feature does the same (workspace `docs/plans/beta3/reorg-parity.md`, R1(b), test T1).

On the plumbing of `rpc_ycash_parity.py`. Two ycashd nodes A and B and one koganyd K share 200
blocks. Only ycashd mines; every block reaches the other nodes through `submitblock`, so no
peer-to-peer link is involved and kogany's regtest proof-of-work waiver does not matter. For a
rollback depth d: A mines d blocks (K gets them), B mines d + 1 on the common tip (K gets them),
then A gets B's blocks. Expected:

    d = 99         A follows B; K has the same best block as A.
    d = 100, 101   A exits, its output has "would roll back d blocks!"; K exits with the same
                   sentence, and its last best block is its old tip (A's).

After a refusal both nodes are started again: each must stop again. K is then started once more
with the non-finalized backup off and must stop again, never answering with B's branch. Depth 99
and depth 100 run on one chain (99 first); every further refused depth needs new nodes, and
gets them.

Then, where K keeps the non-finalized backup, the operator's step: K's record of the refusal
(`ycash-reorg-refused`) is removed and K is started again. Its backup holds both branches, the
stored part of B's with exactly the work of K's own chain (regtest: every block has the same
work), and restored blocks have no receipt order. K must come back on its old tip, never on
B's branch, and stop again, with a new record, when it is given the switching block again.

Last, `invalidateblock` (`--invalidate-depths`, new nodes for each depth). ycashd's
`InvalidateBlock` disconnects down to the parent of the invalidated block without asking the
depth (`src/main.cpp:5245-5267`), and the `ActivateBestChain` that follows
(`src/rpc/blockchain.cpp:2175`) asks it from that parent. A mines d + 2 blocks (K gets them), B
mines d + 1 on the common tip (A and K store them: less work than their chain), and A and K are
told to invalidate block d + 1 of A's chain, whose parent is d blocks above the fork point. B's
branch has more work than the d blocks left. Expected:

    d = 99    A and K answer null and follow B: the same best block.
    d = 100   A answers null and exits with "would roll back 100 blocks!", having marked the
              block invalid and disconnected to its parent; started again, it stops again. K
              answers an error and exits (status 1) with the same sentence and a record, having
              changed nothing; started again without the record, it is on its old tip.

Exit status 0 when every expectation holds, 1 otherwise, 2 on a harness error. Stdlib only.
"""

import argparse
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rpc_ycash_parity import (  # noqa: E402
    DEFAULT_YCASH6_BIN, Node, RpcError, start_ycashd, start_zakurad, stop, wait_up, zakurad_toml,
)

SHARED_BLOCKS = 200
MAX_REORG_LENGTH = 99        # ycash6 src/main.h:69
SENTENCE = 'A block chain reorganization has been detected that would roll back %d blocks!'
RECORD = 'ycash-reorg-refused'
BACKUP_OFF = 'ephemeral = false\nshould_backup_non_finalized_state = false\n'


class Failure(Exception):
    pass


def check(condition, what):
    if not condition:
        raise Failure(what)
    print('  ok: %s' % what)


def read(path):
    try:
        with open(path, errors='replace') as f:
            return f.read()
    except FileNotFoundError:
        return ''


def wait_exit(proc, what, timeout=120):
    try:
        return proc.wait(timeout)
    except Exception:
        raise Failure('%s is still running after %d s' % (what, timeout))


class Scene:
    """Two ycashd (A, B) and one koganyd (K) in `workdir`, each with its own ports."""

    def __init__(self, args, workdir, base, backup):
        self.args, self.workdir, self.base, self.backup = args, workdir, base, backup
        self.dirs = {name: os.path.join(workdir, name) for name in 'ABK'}
        for d in self.dirs.values():
            os.makedirs(d, exist_ok=True)
        self.a = Node('ycashd A', base + 1, 'u:p')
        self.b = Node('ycashd B', base + 3, 'u:p')
        self.k = Node('koganyd K', base + 11)
        self.procs = {}
        self.miner = None    # an address of A, for kogany's [mining] section; K never mines

    def start_a(self):
        self.procs['A'] = start_ycashd(self.args.ycash6_bin, self.dirs['A'], self.base, self.base + 1)

    def start_b(self):
        self.procs['B'] = start_ycashd(self.args.ycash6_bin, self.dirs['B'], self.base + 2, self.base + 3)

    def start_k(self, backup=None):
        toml = zakurad_toml(self.dirs['K'], self.base + 10, self.base + 11, self.base + 12, self.miner)
        if not (self.backup if backup is None else backup):
            assert 'ephemeral = false\n' in toml
            toml = toml.replace('ephemeral = false\n', BACKUP_OFF)
        self.procs['K'] = start_zakurad(self.args.zakurad, self.dirs['K'], toml)

    def start(self):
        self.start_a()
        self.start_b()
        wait_up(self.a, self.procs['A'], 'ycashd A')
        wait_up(self.b, self.procs['B'], 'ycashd B')
        self.miner = self.a.ok('getnewaddress')
        self.start_k()
        wait_up(self.k, self.procs['K'], 'koganyd K')

    def stop(self):
        for proc in self.procs.values():
            stop(proc)

    def out(self, name):
        """What the node printed, and for ycashd its debug log."""
        if name == 'K':
            return read(os.path.join(self.dirs['K'], 'zakurad.out'))
        return (read(os.path.join(self.dirs[name], 'ycashd.out'))
                + read(os.path.join(self.dirs[name], 'ycashd', 'regtest', 'debug.log')))

    def mine(self, miner, n, to):
        """Mine `n` blocks on `miner` and submit each to the nodes in `to`. Returns the raw blocks."""
        blocks = []
        for h in miner.ok('generate', n):
            raw = miner.ok('getblock', h, 0)
            blocks.append(raw)
            for node in to:
                result = node.ok('submitblock', raw)
                # A block off the best chain answers "inconclusive" on ycashd.
                if result not in (None, 'inconclusive', 'duplicate'):
                    raise RpcError('%s refused block %s: %r' % (node.name, h, result))
        return blocks

    def same_tip(self, node, want, what, timeout=60):
        deadline = time.time() + timeout
        tip = None
        while time.time() < deadline:
            tip = node.ok('getbestblockhash')
            if tip == want:
                break
            time.sleep(0.2)
        check(tip == want, what)

    def offer(self, node, proc, blocks):
        """Submit `blocks` until the node stops answering or all are in. Returns its answers."""
        answers = []
        for raw in blocks:
            if proc.poll() is not None:
                break
            try:
                answers.append(node.call('submitblock', raw))
            except RpcError as e:
                answers.append(('unreachable', str(e)))
                break
        return answers

    def refused(self, name, proc, depth, when):
        code = wait_exit(proc, name)
        out = self.out(name)
        check(SENTENCE % depth in out, '%s %s: stopped with "would roll back %d blocks!" (exit %s)'
              % (name, when, depth, code))

    def restart_refused(self, depth, old_tip):
        """Both nodes stop again when started again; K also with the backup off."""
        seen = self.out('A').count(SENTENCE % depth)
        self.start_a()
        code = wait_exit(self.procs['A'], 'ycashd A (restarted)')
        check(self.out('A').count(SENTENCE % depth) > seen,
              'A restarted: stops again with the sentence (exit %s)' % code)
        for backup, label in ((self.backup, 'as configured'), (False, 'backup off')):
            seen = self.out('K').count(SENTENCE % depth)
            self.start_k(backup)
            proc, answers = self.procs['K'], set()
            deadline = time.time() + 120
            while proc.poll() is None and time.time() < deadline:
                try:
                    tip, error = self.k.call('getbestblockhash')
                    if not error:
                        answers.add(tip)
                except RpcError:
                    pass
                time.sleep(0.2)
            code = wait_exit(proc, 'koganyd K (restarted, %s)' % label, 5)
            check(self.out('K').count(SENTENCE % depth) > seen,
                  'K restarted (%s): stops again with the sentence (exit %s)' % (label, code))
            check(code == 1, 'K restarted (%s): an orderly exit with status 1, not a panic' % label)
            check(answers <= {old_tip},
                  'K restarted (%s): never answered with another tip than its old one (%s)'
                  % (label, sorted(answers) or 'no answer'))

    def records(self):
        """K's records of a refused reorganisation (one state database, so at most one)."""
        return [os.path.join(root, RECORD) for root, _, files in os.walk(self.dirs['K'])
                if RECORD in files]

    def record_removed(self, depth, old_tip, new_tip, switching):
        """The operator removes K's record and starts it with its backup: K is on its old tip."""
        records = self.records()
        check(len(records) == 1, 'K has one record of the refusal (%s)' % records)
        check((SENTENCE % depth) in read(records[0]), 'the record holds the sentence')
        os.remove(records[0])
        seen = self.out('K').count(SENTENCE % depth)
        self.start_k(True)
        proc = self.procs['K']
        wait_up(self.k, proc, 'koganyd K (record removed)')
        answers = set()
        deadline = time.time() + 10
        while proc.poll() is None and time.time() < deadline:
            try:
                tip, error = self.k.call('getbestblockhash')
                if not error:
                    answers.add(tip)
            except RpcError:
                pass
            time.sleep(0.2)
        check(new_tip not in answers and answers == {old_tip},
              'K restarted without the record: on its old tip, never on B\'s branch (%s)'
              % sorted(answers))
        check(proc.poll() is None and not self.records(),
              'K restarted without the record: running, and no new record')
        self.offer(self.k, proc, switching)
        code = wait_exit(proc, 'koganyd K (record removed, given the switching block)')
        check(self.out('K').count(SENTENCE % depth) > seen and code == 1,
              'K given the switching block again: stops again with the sentence (exit %s)' % code)
        check(len(self.records()) == 1, 'K recorded the refusal again')

    def round(self, depth):
        a, b, k = self.a, self.b, self.k
        base_tip = a.ok('getbestblockhash')
        check(b.ok('getbestblockhash') == base_tip and k.ok('getbestblockhash') == base_tip,
              'depth %d: A, B and K start on one tip at height %d' % (depth, a.ok('getblockcount')))
        self.mine(a, depth, [k])
        old_tip = a.ok('getbestblockhash')
        self.same_tip(k, old_tip, 'depth %d: K follows A for %d blocks' % (depth, depth))
        branch = [b.ok('getblock', h, 0) for h in b.ok('generate', depth + 1)]
        new_tip = b.ok('getbestblockhash')

        if depth <= MAX_REORG_LENGTH:
            for node in (k, a):
                answers = self.offer(node, self.procs['K' if node is k else 'A'], branch)
                check(len(answers) == len(branch), 'depth %d: %s took all %d blocks of B'
                      % (depth, node.name, len(branch)))
            self.same_tip(a, new_tip, 'depth %d: A follows B (rolls back %d blocks)' % (depth, depth))
            self.same_tip(k, new_tip, 'depth %d: K has the same best block as A' % depth)
            check(self.procs['A'].poll() is None and self.procs['K'].poll() is None,
                  'depth %d: A and K are still running' % depth)
            return

        # K first: its old tip must be its best block until the block that would switch it.
        self.offer(k, self.procs['K'], branch[:-1])
        self.same_tip(k, old_tip, 'depth %d: K keeps its tip with %d blocks of B stored' % (depth, depth))
        self.offer(k, self.procs['K'], branch[-1:])
        self.refused('K', self.procs['K'], depth, 'at depth %d' % depth)
        self.offer(a, self.procs['A'], branch)
        self.refused('A', self.procs['A'], depth, 'at depth %d' % depth)
        self.restart_refused(depth, old_tip)
        if self.backup:
            self.record_removed(depth, old_tip, b.ok('getblockhash', b.ok('getblockcount') - 1),
                                branch[-1:])


    def invalidate_round(self, depth):
        a, b, k = self.a, self.b, self.k
        fork_height = a.ok('getblockcount')
        self.mine(a, depth + 2, [k])
        old_tip = a.ok('getbestblockhash')
        self.same_tip(k, old_tip, 'invalidate %d: K follows A for %d blocks' % (depth, depth + 2))
        branch = [b.ok('getblock', h, 0) for h in b.ok('generate', depth + 1)]
        new_tip = b.ok('getbestblockhash')
        for node, name in ((k, 'K'), (a, 'A')):
            answers = self.offer(node, self.procs[name], branch)
            check(len(answers) == len(branch) and node.ok('getbestblockhash') == old_tip,
                  'invalidate %d: %s stores B\'s %d blocks and keeps its tip'
                  % (depth, name, len(branch)))
        target = a.ok('getblockhash', fork_height + depth + 1)
        parent = a.ok('getblockhash', fork_height + depth)

        if depth <= MAX_REORG_LENGTH:
            for node in (a, k):
                result, error = node.call('invalidateblock', target)
                check(result is None and not error,
                      'invalidate %d: %s answers null' % (depth, node.name))
            self.same_tip(a, new_tip, 'invalidate %d: A follows B (%d blocks below the parent)'
                          % (depth, depth))
            self.same_tip(k, new_tip, 'invalidate %d: K has the same best block as A' % depth)
            check(self.procs['A'].poll() is None and self.procs['K'].poll() is None,
                  'invalidate %d: A and K are still running' % depth)
            return

        # ycashd: null, the block invalid and the chain cut to its parent, then the shutdown.
        result, error = a.call('invalidateblock', target)
        check(result is None and not error, 'invalidate %d: A answers null' % depth)
        self.refused('A', self.procs['A'], depth, 'after invalidateblock, %d below the parent' % depth)
        seen = self.out('A').count(SENTENCE % depth)
        self.start_a()
        code = wait_exit(self.procs['A'], 'ycashd A (restarted)')
        out = self.out('A')
        check(out.count(SENTENCE % depth) > seen,
              'invalidate %d: A restarted stops again with the sentence (exit %s)' % (depth, code))
        check('Current tip: %s' % parent in out,
              'invalidate %d: A measured from the parent of the invalidated block' % depth)

        # koganyd: an error, nothing changed, the record, the exit.
        try:
            result, error = k.call('invalidateblock', target)
        except RpcError as e:
            result, error = None, str(e)
        check(error, 'invalidate %d: K answers an error (%s)' % (depth, str(error)[:120]))
        self.refused('K', self.procs['K'], depth, 'on invalidateblock, %d below the parent' % depth)
        check(self.procs['K'].returncode == 1, 'invalidate %d: K exits with status 1' % depth)
        records = self.records()
        check(len(records) == 1 and 'Current tip: %s' % parent in read(records[0]),
              'invalidate %d: K recorded the refusal, measured from the same parent' % depth)
        if self.backup:
            os.remove(records[0])
            self.start_k(True)
            wait_up(self.k, self.procs['K'], 'koganyd K (record removed)')
            check(k.ok('getbestblockhash') == old_tip and k.ok('getblockhash', fork_height + depth + 1) == target,
                  'invalidate %d: K restarted without the record is on its old tip, the block not invalidated'
                  % depth)


def run_invalidate_scene(args, workdir, base, depth):
    print('scene %s: invalidateblock, %d blocks below the parent' % (os.path.basename(workdir), depth))
    scene = Scene(args, workdir, base, True)
    try:
        scene.start()
        scene.mine(scene.a, SHARED_BLOCKS, [scene.b, scene.k])
        scene.invalidate_round(depth)
    finally:
        scene.stop()


def run_scene(args, workdir, base, depths, backup):
    print('scene %s: depths %s, non-finalized backup %s' % (os.path.basename(workdir), depths,
                                                           'on' if backup else 'off'))
    scene = Scene(args, workdir, base, backup)
    try:
        scene.start()
        scene.mine(scene.a, SHARED_BLOCKS, [scene.b, scene.k])
        for depth in depths:
            scene.round(depth)
    finally:
        scene.stop()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--koganyd', '--zakurad', dest='zakurad', default=os.getenv('KOGANY_BIN'),
                    help='koganyd (the --features ycash build)')
    ap.add_argument('--ycash6-bin', default=DEFAULT_YCASH6_BIN, help='directory holding ycashd')
    ap.add_argument('--workdir', help='keep the datadirs here (default: a temporary directory)')
    ap.add_argument('--keep', action='store_true', help='keep the temporary directory')
    ap.add_argument('--port-base', type=int, default=28700)
    ap.add_argument('--depths', default='99,100,101', help='rollback depths, comma separated')
    ap.add_argument('--invalidate-depths', default='99,100',
                    help='depths below the parent for the invalidateblock scenes, comma separated '
                         '(empty: none)')
    args = ap.parse_args(argv)
    if not args.zakurad:
        ap.error('--koganyd (or KOGANY_BIN) is required')
    depths = sorted(int(d) for d in args.depths.split(',') if d)
    invalidate_depths = sorted(int(d) for d in args.invalidate_depths.split(',') if d)
    followed = [d for d in depths if d <= MAX_REORG_LENGTH]
    refused = [d for d in depths if d > MAX_REORG_LENGTH]
    # A refusal ends its nodes: the followed depths and the first refused one share a chain, each
    # further refused depth gets new nodes. The backup is on in the first scene, off in the next.
    scenes = [s for s in [followed + refused[:1]] + [[d] for d in refused[1:]] if s]
    workdir = args.workdir or tempfile.mkdtemp(prefix='reorg-parity-')
    status = 0
    try:
        for i, scene_depths in enumerate(scenes):
            run_scene(args, os.path.join(workdir, 'scene%d' % i), args.port_base + 20 * i,
                      scene_depths, backup=(i % 2 == 0))
        for i, depth in enumerate(invalidate_depths, len(scenes)):
            run_invalidate_scene(args, os.path.join(workdir, 'scene%d' % i),
                                 args.port_base + 20 * i, depth)
        print('reorg_parity: every expectation holds for depths %s and invalidateblock at %s'
              % (depths, invalidate_depths))
    except Failure as e:
        print('reorg_parity: FAILED: %s' % e, file=sys.stderr)
        status = 1
    except RpcError as e:
        print('reorg_parity: %s' % e, file=sys.stderr)
        status = 2
    if not args.keep and not args.workdir and status == 0:
        shutil.rmtree(workdir, ignore_errors=True)
    else:
        print('datadirs: %s' % workdir)
    return status


if __name__ == '__main__':
    sys.exit(main())
