//! Ycash Equihash: `(200, 9)` below the Ycash upgrade, `(192, 7)` from it on, bound to the network
//! and the height, never to the solution length (kogany W1-Y2, survey B trap T3).
//!
//! The blocks are real Ycash mainnet blocks, `testdata/ycash-mainnet/` (provenance in
//! `PROVENANCE.json` there): fetched over P2P from `lite.ycash.xyz:8833` (`/YcashCpp:4.5.0/`,
//! protocol 270013) after a getheaders walk from ycash6's checkpoint at 525,000; 570,000 is
//! ycash6's pinned `UPGRADE_YCASH.hashActivationBlock`.

use proptest::prelude::*;

use crate::{
    block::{Block, Hash, Height},
    parameters::Network,
    serialization::{SerializationError, ZcashDeserializeInto},
    work::equihash::{Error, Solution, REGTEST_SOLUTION_SIZE, SOLUTION_SIZE, YCASH_SOLUTION_SIZE},
};

/// `(height, block hash, block hex)` for the last pre-fork and the first two post-fork blocks.
const BLOCKS: &[(u32, &str, &str)] = &[
    (
        569_999,
        "00000000010a9ca077c0d28131861d0644befbb13f229e014c9f3e52d97e4650",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/ycash-mainnet/569999.hex"
        )),
    ),
    (
        570_000,
        "0000014fbc5917ba8bcacf3336faf588d86b32443aa3a490a587af5750c77ec5",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/ycash-mainnet/570000.hex"
        )),
    ),
    (
        570_001,
        "00000050eaff1a1019cb0634ee8c082580a287a591ef333874d2f877ca179059",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/ycash-mainnet/570001.hex"
        )),
    ),
];

fn block(hex_block: &str) -> Block {
    hex::decode(hex_block.trim())
        .expect("test vector is hex")
        .zcash_deserialize_into()
        .expect("a real Ycash mainnet block parses in a ycash build")
}

#[test]
fn real_ycash_headers_verify_at_their_heights() {
    let _init_guard = zakura_test::init();

    for &(height, hash, hex_block) in BLOCKS {
        let block = block(hex_block);
        let header = &block.header;
        let height = Height(height);

        assert_eq!(header.hash(), hash.parse::<Hash>().expect("hash parses"));
        assert_eq!(block.coinbase_height(), Some(height));

        let expected_variant_is_ycash = height >= Height(570_000);
        assert_eq!(
            matches!(header.solution, Solution::Ycash(_)),
            expected_variant_is_ycash,
            "solution shape at {height:?}"
        );

        header
            .solution
            .check(header, &Network::Mainnet, height)
            .unwrap_or_else(|error| panic!("real block at {height:?} must verify: {error}"));
    }
}

#[test]
fn real_solutions_reject_on_the_other_side_of_the_fork() {
    let _init_guard = zakura_test::init();

    let pre = block(BLOCKS[0].2);
    let post = block(BLOCKS[1].2);

    // A real (200, 9) proof is refused where (192, 7) is required, and the reverse, on size,
    // before the verifier runs.
    for (header, height) in [
        (&pre.header, Height(570_000)),
        (&post.header, Height(569_999)),
    ] {
        assert!(
            matches!(
                header.solution.check(header, &Network::Mainnet, height),
                Err(Error::InvalidSolutionSize { .. })
            ),
            "{height:?}"
        );
    }

    // The 400-byte variant is never accepted off Ycash mainnet/testnet's post-fork range.
    assert!(post
        .header
        .solution
        .check(
            &post.header,
            &Network::new_regtest(Default::default()),
            Height(570_000)
        )
        .is_err());
}

#[test]
fn a_tampered_ycash_solution_fails_equihash() {
    let _init_guard = zakura_test::init();

    let post = block(BLOCKS[1].2);
    let mut header = *post.header;
    let Solution::Ycash(mut bytes) = header.solution else {
        panic!("post-fork solution is the Ycash variant");
    };
    bytes[200] ^= 1;
    header.solution = Solution::Ycash(bytes);
    assert!(matches!(
        header
            .solution
            .check(&header, &Network::Mainnet, Height(570_000)),
        Err(Error::Equihash(_))
    ));

    let mut header = *post.header;
    header.nonce.0[0] ^= 1;
    assert!(matches!(
        header
            .solution
            .check(&header, &Network::Mainnet, Height(570_000)),
        Err(Error::Equihash(_))
    ));
}

#[test]
fn shapes_follow_network_and_height() {
    let common = Solution::Common([0; SOLUTION_SIZE]);
    let ycash = Solution::Ycash([0; YCASH_SOLUTION_SIZE]);
    let regtest_solution = Solution::Regtest([0; REGTEST_SOLUTION_SIZE]);
    let testnet = Network::new_default_testnet();
    let regtest = Network::new_regtest(Default::default());

    for (network, fork) in [(Network::Mainnet, 570_000), (testnet, 510_248)] {
        for (height, common_ok) in [
            (1, true),
            (fork - 1, true),
            (fork, false),
            (u32::MAX >> 1, false),
        ] {
            let height = Height(height);
            assert_eq!(common.validate_shape(&network, height).is_ok(), common_ok);
            assert_eq!(ycash.validate_shape(&network, height).is_ok(), !common_ok);
            assert!(regtest_solution.validate_shape(&network, height).is_err());
        }
    }

    // Regtest is (48, 5) under every upgrade, as on ycashd.
    for height in [Height(1), Height(570_000)] {
        assert!(regtest_solution.validate_shape(&regtest, height).is_ok());
        assert!(common.validate_shape(&regtest, height).is_err());
        assert!(ycash.validate_shape(&regtest, height).is_err());
    }

    assert_eq!(
        Solution::for_proposal_for_network(&Network::Mainnet),
        ycash,
        "a proposal is for a post-fork block"
    );
}

proptest! {
    /// Fuzz on the solution length: only 36, 400 and 1344 bytes parse, and each parsed shape is
    /// accepted only where the network and height require it.
    #[test]
    fn solution_length_never_selects_parameters(len in 0usize..2_000, height in 0u32..2_000_000) {
        let bytes = vec![0u8; len];
        let parsed = Solution::from_bytes(&bytes);
        prop_assert_eq!(
            parsed.is_ok(),
            matches!(len, REGTEST_SOLUTION_SIZE | YCASH_SOLUTION_SIZE | SOLUTION_SIZE)
        );
        if parsed.is_err() {
            prop_assert!(matches!(parsed, Err(SerializationError::Parse(_))));
        }

        let mut wire = Vec::new();
        let size = crate::serialization::CompactSizeMessage::try_from(len).expect("length fits");
        crate::serialization::ZcashSerialize::zcash_serialize(&size, &mut wire)
            .expect("writing to a vec succeeds");
        wire.extend_from_slice(&bytes);
        let deserialized: Result<Solution, _> = wire.zcash_deserialize_into();
        prop_assert_eq!(deserialized.is_ok(), parsed.is_ok());

        if let Ok(solution) = parsed {
            let height = Height(height);
            let mainnet_ok = solution.validate_shape(&Network::Mainnet, height).is_ok();
            let expected = if height >= Height(570_000) {
                len == YCASH_SOLUTION_SIZE
            } else {
                len == SOLUTION_SIZE
            };
            prop_assert_eq!(mainnet_ok, expected);
        }
    }
}
