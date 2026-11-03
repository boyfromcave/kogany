//! kogany (W7-e): ycashd's `nMockTime` (`src/utiltime.cpp` `SetMockTime`, `GetTime`), the clock
//! the regtest-only `setmocktime` RPC sets.
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! One value per process, as in ycashd. It is read where ycashd's `GetTime()` reaches an RPC
//! answer kogany serves: the `getblocktemplate` `curtime` (under the `ycash` feature) and the
//! YED miner quote's age (`kogany-rpc`). Consensus time checks (a block's time against the local
//! clock) keep the system clock. Unset, every reader sees the system clock.

use std::sync::atomic::{AtomicI64, Ordering};

/// The mock time in Unix seconds; `0` is unset (ycashd's `nMockTime == 0`).
static MOCK_TIME: AtomicI64 = AtomicI64::new(0);

/// Sets the mock time to `unix_seconds`; `0` goes back to the system clock (`SetMockTime`).
pub fn set_mock_time(unix_seconds: i64) {
    MOCK_TIME.store(unix_seconds, Ordering::SeqCst);
}

/// The mock time, `None` when unset.
pub fn mock_time() -> Option<i64> {
    let time = MOCK_TIME.load(Ordering::SeqCst);
    (time != 0).then_some(time)
}

/// The node's time in Unix seconds: the mock time when set, else the system clock (`GetTime`).
pub fn now() -> i64 {
    mock_time().unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
            })
    })
}
