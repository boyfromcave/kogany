//! The header chain's proof-of-work policy binds Equihash to the header's height on Ycash: real
//! mainnet headers at 569,999 `(200, 9)` and 570,000 `(192, 7)` accept, swapped heights reject.
//! Blocks: `testdata/ycash-mainnet/` (P2P from `lite.ycash.xyz:8833`, `PROVENANCE.json`).

use super::super::*;
use zakura_chain::{
    block::{Block, Height},
    parameters::Network,
    serialization::ZcashDeserializeInto,
    work::equihash,
};

fn block_from_hex(hex_block: &str) -> Block {
    let hex_block = hex_block.trim();
    let bytes: Vec<u8> = (0..hex_block.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_block[i..i + 2], 16).expect("test vector is hex"))
        .collect();
    bytes
        .zcash_deserialize_into()
        .expect("a real Ycash mainnet block parses in a ycash build")
}

#[test]
fn pow_policy_follows_the_ycash_fork_height() {
    let pre = block_from_hex(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/ycash-mainnet/569999.hex"
    )));
    let post = block_from_hex(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/ycash-mainnet/570000.hex"
    )));
    let policy = PowPolicy::validating(&Network::Mainnet);

    policy
        .validate_solution(&pre.header, Height(569_999))
        .expect("the last pre-fork header verifies under (200, 9)");
    policy
        .validate_solution(&post.header, Height(570_000))
        .expect("the fork block's header verifies under (192, 7)");

    for (header, height) in [
        (&pre.header, Height(570_000)),
        (&post.header, Height(569_999)),
    ] {
        assert!(matches!(
            policy.validate_solution(header, height),
            Err(equihash::Error::InvalidSolutionSize { .. })
        ));
    }
}
