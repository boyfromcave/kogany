#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Tests for qa/kogany_sync_gate.py and qa/kogany_checkpoints.py
(run: python3 -m unittest discover -s qa -p 'test_kogany_*.py')."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kogany_checkpoints as checkpoints  # noqa: E402
import kogany_sync_gate as gate  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def block(**fields):
    b = {"hash": "aa", "finalsaplingroot": "00",
         "chainSupply": {"monitored": True, "chainValueZat": 10, "valueDeltaZat": 1},
         "valuePools": [{"id": "transparent", "monitored": True, "chainValueZat": 7, "valueDeltaZat": 1},
                        {"id": "sprout", "monitored": True, "chainValueZat": 3, "valueDeltaZat": 0}]}
    b.update(fields)
    return b


class SyncGateTest(unittest.TestCase):
    def test_identical_blocks_compare_equal(self):
        self.assertEqual(gate.compare_blocks(5, block(), block()), [])

    def test_a_pool_difference_is_reported(self):
        y = block(valuePools=[{"id": "transparent", "monitored": True, "chainValueZat": 8, "valueDeltaZat": 1}])
        self.assertEqual(gate.compare_blocks(5, block(), y), [("valuePools.transparent.chainValueZat", 7, 8)])

    def test_unmonitored_pools_and_extra_pools_are_not_compared(self):
        k = block(valuePools=block()["valuePools"] + [{"id": "ironwood", "monitored": False, "chainValueZat": 0}])
        y = block(valuePools=[dict(block()["valuePools"][0]), {"id": "sprout", "monitored": False, "chainValueZat": 9}])
        self.assertEqual(gate.compare_blocks(5, k, y), [])

    def test_blockcommitments_only_from_heartwood(self):
        k, y = block(blockcommitments="01"), block(blockcommitments="02")
        self.assertEqual(gate.compare_blocks(gate.MAINNET_HEARTWOOD - 1, k, y), [])
        self.assertEqual(len(gate.compare_blocks(gate.MAINNET_HEARTWOOD, k, y)), 1)

    def test_treestates_compare_the_shared_fields(self):
        k = {"sapling": {"commitments": {"finalState": "ab"}}, "orchard": {"commitments": {}}}
        y = {"sapling": {"commitments": {"finalState": "ab", "finalRoot": "cd"}},
             "sprout": {"commitments": {"finalState": "ef"}}}
        self.assertEqual(gate.compare_treestates(k, y), (["sapling.finalState"], []))

    def test_chainhistoryroot_is_the_blocks_own_commitment(self):
        h = gate.MAINNET_HEARTWOOD + 1
        same = block(blockcommitments="84", chainhistoryroot="84")
        self.assertEqual(gate.compare_blocks(h, block(blockcommitments="84"), same), [])
        other = block(blockcommitments="84", chainhistoryroot="8d")
        self.assertEqual([d[0] for d in gate.compare_blocks(h, block(blockcommitments="84"), other)],
                         ["zip221 chainhistoryroot(h) vs blockcommitments(h)"])
        self.assertEqual(gate.compare_blocks(gate.MAINNET_HEARTWOOD, block(blockcommitments="00"),
                                             block(blockcommitments="00", chainhistoryroot="84")), [])

    def test_recheck_keeps_only_the_differences_that_remain(self):
        class Fake:
            def __init__(self, blocks, trees):
                self.blocks, self.trees = blocks, trees
            def batch(self, calls):
                return [(self.blocks[int(p[0])], None) for _, p in calls]
            def call(self, method, height):
                return self.trees[int(height)]
        tree = lambda st: {"sapling": {"commitments": {"finalState": st, "finalRoot": "r"}}}
        kogany = Fake({5: block(finalsaplingroot="3e"), 6: block(finalsaplingroot="00")},
                      {9: tree("01"), 10: tree("02")})
        ycash = Fake({5: block(finalsaplingroot="3e"), 6: block(finalsaplingroot="3e")},
                     {9: tree("01"), 10: tree("03")})
        state = {"compared_through": 10, "rounds": 1,
                 "mismatches": [{"height": 5, "diffs": [["finalsaplingroot", "00", "3e"]]},
                                {"height": 6, "diffs": [["finalsaplingroot", "00", "3e"]]},
                                {"height": 9, "diffs": [["sapling.finalState", "0100", "01"]], "rpc": "z_gettreestate"}],
                 "treestate_samples": [{"height": 9, "fields": [], "identical": False},
                                       {"height": 10, "fields": [], "identical": False}]}
        args = type("A", (), {"batch": 100, "state": None})()
        gate.recheck(kogany, ycash, state, args)
        self.assertEqual([m["height"] for m in state["mismatches"]], [6, 10])
        self.assertEqual([t["identical"] for t in state["treestate_samples"]], [True, False])
        self.assertEqual(state["rechecks"][-1]["mismatches_before"], 3)

    def test_log_scan_separates_the_list_end(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("block could not be checkpointed due to: block at Height(500) is higher than the maximum checkpoint Height(400)\n")
            f.write("block could not be full-verified due to: bad thing at Height(300)\n")
            f.write("block could not be checkpointed due to: something at Height(900)\n")
            f.write("WARN error downloading and verifying block e=Invalid { error: Checkpoint { source: Finished }, height: Height(410), \n")
        try:
            rejected, beyond, samples = gate.scan_log(f.name, 400)
        finally:
            os.unlink(f.name)
        self.assertEqual((rejected, beyond, len(samples)), (1, 3, 1))


class CheckpointsTest(unittest.TestCase):
    def test_the_committed_lists_hold_their_invariants(self):
        for network, path, upstream, pins, vault, shared in (
            ("mainnet", checkpoints.YCASH_MAINNET, checkpoints.UPSTREAM_MAINNET, checkpoints.MAINNET_PINS,
             checkpoints.MAINNET_VAULT_HEIGHT, checkpoints.YCASH_FORK_HEIGHT),
            ("testnet", checkpoints.YCASH_TESTNET, checkpoints.UPSTREAM_TESTNET, checkpoints.TESTNET_PINS,
             checkpoints.TESTNET_VAULT_HEIGHT, checkpoints.TESTNET_LAST_SHARED_HEIGHT + 1),
        ):
            header, entries = checkpoints.read_list(os.path.join(REPO, path))
            _, up = checkpoints.read_list(os.path.join(REPO, upstream))
            summary = checkpoints.check_list(entries, pins, vault, up, shared)
            self.assertIn(0, summary["pins_covered"], network)
            self.assertTrue(any(line.startswith("# PARTIAL") or line.startswith("# COMPLETE") for line in header))

    def test_a_wrong_pin_or_a_vault_epoch_checkpoint_fails(self):
        entries = [(0, "a" * 64), (400, "b" * 64)]
        with self.assertRaises(checkpoints.CheckpointError):
            checkpoints.check_list(entries, {400: "c" * 64}, None)
        with self.assertRaises(checkpoints.CheckpointError):
            checkpoints.check_list(entries, {}, 400)
        with self.assertRaises(checkpoints.CheckpointError):
            checkpoints.check_list([(0, "a" * 64), (401, "b" * 64)], {}, None)

    def test_generation_follows_the_selection_rule_and_adds_pins(self):
        class FakeRpc:
            def call(self, method, *params):
                return {"blocks": 2500}

            def batch(self, calls):
                return [{"height": int(p[0]), "hash": "%064x" % (int(p[0]) + 1), "size": 1000} for _, p in calls]

        pins = {1000: "%064x" % 1001}
        entries, tip, limit = checkpoints.generate(FakeRpc(), pins, None, [])
        self.assertEqual(limit, 1500)
        self.assertEqual([h for h, _ in entries], [0, 400, 800, 1000, 1200])
        # Resuming drops a trailing pin and continues the rule's own sequence.
        resumed, _, _ = checkpoints.generate(FakeRpc(), pins, None, entries[:4])
        self.assertEqual(resumed, entries)


if __name__ == "__main__":
    unittest.main()
