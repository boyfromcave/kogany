#!/usr/bin/env python3
"""Run a ycash6 vault RPC test unmodified and record, on node 0, every (tip hash, height,
vault_getinfo.statehash) it passes through at a sync point, then the raw blocks of node 0's
active chain. Usage: record_statehash.py <module> <out.json> [test args...]"""

import importlib
import json
import sys


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    modname, out = argv[0], argv[1]
    sys.argv = [modname + '.py'] + argv[2:]
    mod = importlib.import_module(modname)
    from test_framework.test_framework import BitcoinTestFramework
    cls = [c for c in vars(mod).values()
           if isinstance(c, type) and issubclass(c, BitcoinTestFramework) and c is not BitcoinTestFramework
           and c.__module__ == modname][0]
    seen = {}

    def record(self):
        try:
            n = self.nodes[0]
            info = n.vault_getinfo()
            tip = n.getbestblockhash()
            seen[tip] = {'height': n.getblockcount(), 'statehash': info['statehash'], 'dbtip': info.get('dbtip')}
        except Exception:
            pass

    orig_sync_all = cls.sync_all
    def sync_all(self, *a, **k):
        r = orig_sync_all(self, *a, **k)
        record(self)
        return r
    cls.sync_all = sync_all

    orig_run = cls.run_test
    def run_test(self):
        orig_run(self)
        record(self)
        n = self.nodes[0]
        tip = n.getblockcount()
        # Walk back: the state hash after every block of the active chain, read at each tip while
        # disconnecting (the C++ undo path), then the chain reconnected and its tip hash re-checked.
        walked = {}
        top = n.getbestblockhash()
        h = tip
        while h >= 1:
            bh = n.getblockhash(h)
            info = n.vault_getinfo()
            if info.get('statehash') is None:
                break
            walked[bh] = info['statehash']
            if 'dbtip' in info and info['dbtip'] in (None, '', '0' * 64):
                break
            n.invalidateblock(bh)
            h -= 1
        n.reconsiderblock(n.getblockhash(h + 1) if h + 1 <= n.getblockcount() else top)
        for bh in list(walked):
            n.reconsiderblock(bh)
        assert n.getbestblockhash() == top, 'the walk-back did not reconnect the tip'
        assert n.vault_getinfo()['statehash'] == walked[top]
        for k, v in seen.items():
            if k in walked:
                assert walked[k] == v['statehash'], ('connect and walk-back differ', k)
        blocks = []
        for h in range(1, tip + 1):
            bh = n.getblockhash(h)
            blocks.append({'height': h, 'hash': bh, 'hex': n.getblock(bh, 0),
                           'statehash': walked.get(bh)})
        doc = {'source': modname, 'tip': tip, 'blocks': blocks,
               'statehashes': {k: v for k, v in seen.items()}}
        with open(out, 'w') as fh:
            json.dump(doc, fh)
    cls.run_test = run_test
    cls().main()


if __name__ == '__main__':
    main()
