## audit (a) consensus-diff (report-only)

Base `kogany-legacy` (2b062412c5cd), head `7d070b4ee2ee`; path set `qa/kogany-consensus-paths.txt`.

20 file(s) changed:

```
 crates/zakura-chain/src/block/commitment.rs                              |   2 +-
 crates/zakura-chain/src/parameters.rs                                    |   2 +
 crates/zakura-chain/src/parameters/constants.rs                          |   2 +
 crates/zakura-chain/src/parameters/network.rs                            |  12 +++
 crates/zakura-chain/src/parameters/network/error.rs                      |   4 +
 crates/zakura-chain/src/parameters/network/subsidy.rs                    |   9 ++
 crates/zakura-chain/src/parameters/network/subsidy/constants/testnet.rs  |   1 +
 crates/zakura-chain/src/parameters/network/testnet.rs                    |  35 +++++++
 crates/zakura-chain/src/parameters/network_upgrade.rs                    |  39 ++++++-
 crates/zakura-chain/src/parameters/ycash.rs                              | 212 +++++++++++++++++++++++++++++++++++++++
 crates/zakura-chain/src/transaction/arbitrary.rs                         |   7 +-
 crates/zakura-consensus/Cargo.toml                                       |   3 +
 crates/zakura-consensus/src/primitives/halo2.rs                          |   4 +-
 crates/zakura-consensus/src/transaction.rs                               |   2 +
 crates/zakura-consensus/src/transaction/tests.rs                         |   1 +
 crates/zakura-consensus/src/transaction/tests/prop.rs                    |   2 +-
 crates/zakura-consensus/tests/nu7_diff_dump.rs                           |   2 +
 crates/zakura-state/src/service/finalized_state/tests/prop.rs            |   2 +
 crates/zakura-state/src/service/finalized_state/tests/rollback.rs        |   1 +
 crates/zakura-state/src/service/finalized_state/vct_fast_sync_fixture.rs |   1 +
 20 files changed, 333 insertions(+), 10 deletions(-)
```

