// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The module's state machine (chunks W5-d1 and W5-d2, not yet implemented): MINT, transfer,
//! claim intents, cancel (CAN-1/2/3), release, redeem with the early fee, HALT-1/2/3, the supply
//! cap, ejection, `EvaluateBlock` and `MempoolCheckReason` — ycash6 `src/yellowback/
//! {view,state}.{h,cpp}`, over the arithmetic of [`crate::math`] and the columns of
//! [`crate::params`].
