// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Wire formats (chunk W5-b): byte-exact ports, by meaning, of ycash6 `src/yellowback/
//! {payload,script,address,tag}.{h,cpp}` at `65cb4ae0f`, plus the two pieces of
//! `src/script/standard.cpp` and `src/base58.cpp` they reach:
//!
//! | module | ycash6 source | what |
//! |---|---|---|
//! | [`payload`] | `payload.{h,cpp}` | the `"YB"` OP_RETURN payload: the v4 MINT (PQ owner) and the v3 types; `FindPayload` |
//! | [`script`] | `script.{h,cpp}`, `script/standard.cpp` (`MatchPQChannel`) | the YED vault V, holder scripts (TOK-PQ), carrier, bond, the v2 vault |
//! | [`address`] | `address.{h,cpp}` | `yb`/`yt`/`yr` addresses, 35 characters (P2PKH) and 53 (PQ) |
//! | [`base58`] | `base58.cpp` | Base58 and Base58Check with the C++ decoder's exact acceptance |
//! | [`tag`] | `tag.{h,cpp}` | the 36-byte coinbase tag `YED!` and its byte scan |
//!
//! The byte constants live in [`crate::params`] ([`crate::params::PAYLOAD_MAGIC_0`],
//! [`crate::params::TAG_MAGIC`], ...); the script tokenizer, the `CScript <<` builder and the V
//! template are the vault primitive's ([`kogany_vault::script`], [`kogany_vault::template`]).
//!
//! Every function is total: malformed input is `None` (the C++ `false` / empty script /
//! `nullopt`), never a panic. Transactions are not modelled here: the transaction-level helpers
//! ([`payload::find_payload`], [`script::find_carrier_input`]) take the output scripts or input
//! scriptSigs in order.

pub mod address;
pub mod base58;
pub mod payload;
pub mod script;
pub mod tag;
