// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Wire formats (chunk W5-b, not yet implemented): the MINT payload (v4, PQ owner) and the v3
//! payloads, the YED token and carrier scripts, the address encodings (`yb`/`yt`/`yr`, the PQ
//! 53-character forms) and the 36-byte coinbase tag `YED!` — ycash6 `src/yellowback/
//! {payload,script,address,tag}.{h,cpp}`. The byte constants already live in [`crate::params`]
//! ([`crate::params::PAYLOAD_MAGIC_0`], [`crate::params::TAG_MAGIC`], ...).
