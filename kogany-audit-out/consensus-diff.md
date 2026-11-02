## audit (a) consensus-diff (report-only)

Base `kogany-baseline` (23051861a04a), head `9342a0cc0dea`; path set `qa/kogany-consensus-paths.txt`.

35 file(s) changed:

```
 crates/zakura-chain/src/block/commitment.rs                                |   2 +-
 crates/zakura-chain/src/parameters.rs                                      |   4 +
 crates/zakura-chain/src/parameters/constants.rs                            |   2 +
 crates/zakura-chain/src/parameters/network.rs                              |  12 +++
 crates/zakura-chain/src/parameters/network/error.rs                        |   4 +
 crates/zakura-chain/src/parameters/network/subsidy.rs                      |   9 ++
 crates/zakura-chain/src/parameters/network/subsidy/constants/testnet.rs    |   1 +
 crates/zakura-chain/src/parameters/network/testnet.rs                      |  42 ++++++++
 crates/zakura-chain/src/parameters/network/tests/vectors.rs                |   4 +-
 crates/zakura-chain/src/parameters/network_upgrade.rs                      |  60 ++++++++++-
 crates/zakura-chain/src/parameters/tests.rs                                |   8 ++
 crates/zakura-chain/src/parameters/ycash.rs                                | 190 +++++++++++++++++++++++++++++++++++
 crates/zakura-chain/src/parameters/ycash/tests.rs                          | 197 +++++++++++++++++++++++++++++++++++++
 crates/zakura-chain/src/parameters/ycash_dormancy_tests.rs                 |  63 ++++++++++++
 crates/zakura-chain/src/transaction/arbitrary.rs                           |   7 +-
 crates/zakura-chain/src/work/equihash.rs                                   | 162 +++++++++++++++++++++++-------
 crates/zakura-chain/src/work/tests/prop.rs                                 |  12 +--
 crates/zakura-chain/src/work/tests/vectors.rs                              |  47 +++++----
 crates/zakura-consensus/Cargo.toml                                         |   3 +
 crates/zakura-consensus/src/block.rs                                       |   2 +-
 crates/zakura-consensus/src/block/check.rs                                 |   5 +-
 crates/zakura-consensus/src/block/tests.rs                                 |   5 +-
 crates/zakura-consensus/src/checkpoint.rs                                  |   2 +-
 crates/zakura-consensus/src/primitives/halo2.rs                            |   4 +-
 crates/zakura-consensus/src/transaction.rs                                 |   2 +
 crates/zakura-consensus/src/transaction/tests.rs                           |   1 +
 crates/zakura-consensus/src/transaction/tests/prop.rs                      |   2 +-
 crates/zakura-consensus/tests/nu7_diff_dump.rs                             |   2 +
 crates/zakura-header-chain/src/validation/context_free/pow_policy.rs       |  13 ++-
 crates/zakura-header-chain/src/validation/context_free/tests/pow_policy.rs |   6 +-
 crates/zakura-header-chain/src/validation/context_free/trusted_anchor.rs   |   2 +-
 crates/zakura-header-chain/src/validation/prepare/pipeline.rs              |   2 +-
 crates/zakura-state/src/service/finalized_state/tests/prop.rs              |   2 +
 crates/zakura-state/src/service/finalized_state/tests/rollback.rs          |   1 +
 crates/zakura-state/src/service/finalized_state/vct_fast_sync_fixture.rs   |   1 +
 35 files changed, 800 insertions(+), 81 deletions(-)
```

