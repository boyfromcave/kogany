//! A fixed Mainnet work floor for downloaded block admission.
//!
//! This is a resource policy, separate from consensus validation. If Mainnet
//! difficulty falls below this floor, otherwise valid downloaded blocks will be
//! refused until the policy is updated. Rejections must not score peers or mark
//! blocks consensus-invalid.

use zakura_chain::{block::Height, parameters::Network, work::difficulty::CompactDifficulty};

/// Last Mainnet checkpoint when the admission floor was introduced.
///
/// Apply the floor immediately above this boundary so choosing an older height
/// cannot bypass it on the default full-verification path.
const MAINNET_WORK_FLOOR_HEIGHT: Height = Height(3_535_411);

/// Target of Mainnet block 3,538,452, observed on November 1, 2026 UTC.
///
/// Block hash:
/// `0000000000044089828cb43eee6f528cb2e333cc1380b4308fc07a7babd01bd1`.
/// Source: <https://ccnodes.net/explorer/v1/zcash/blocks>.
const MAINNET_REFERENCE_TARGET: CompactDifficulty =
    CompactDifficulty::from_le_bytes(0x1b6aac57_u32.to_le_bytes());

/// Allow one tenth of the reference difficulty: targets at most ten times larger.
const MAINNET_TARGET_MULTIPLIER: u32 = 10;

/// Whether a downloaded header's claimed target meets the admission work floor.
///
/// This does not verify the header hash or Equihash solution, or replace the
/// parent-dependent difficulty check. Earlier Mainnet blocks and other networks
/// retain their existing validation rules.
pub(super) fn has_sufficient_work(
    network: &Network,
    height: Height,
    target: CompactDifficulty,
) -> bool {
    // kogany: the floor's height and reference target are Zcash Mainnet's. Ycash Mainnet's
    // difficulty is far below a tenth of Zcash's, so above 3,535,411 every Ycash block would be
    // refused and sync would stop; ycashd has no such floor. With `ycash` there is none until a
    // Ycash reference is calibrated.
    if cfg!(feature = "ycash") {
        return true;
    }

    if !matches!(network, Network::Mainnet) || height <= MAINNET_WORK_FLOOR_HEIGHT {
        return true;
    }

    // The fixed reference is valid, and multiplying its 215-bit target by ten
    // fits in the 256-bit expanded target representation.
    let max_target = MAINNET_REFERENCE_TARGET
        .to_expanded()
        .expect("the fixed Mainnet reference target has a valid compact encoding")
        * MAINNET_TARGET_MULTIPLIER;

    target
        .to_expanded()
        .is_some_and(|target| target <= max_target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zakura_chain::work::difficulty::ParameterDifficulty as _;

    #[test]
    // kogany: Zcash Mainnet's floor; with `ycash` there is none (see `has_sufficient_work`).
    #[cfg(not(feature = "ycash"))]
    fn mainnet_work_floor_covers_the_default_semantic_path() {
        assert!(MAINNET_WORK_FLOOR_HEIGHT <= Network::Mainnet.checkpoint_list().max_height());
    }

    #[test]
    // kogany: Zcash Mainnet's floor; with `ycash` there is none (see `has_sufficient_work`).
    #[cfg(not(feature = "ycash"))]
    fn mainnet_work_floor_preserves_earlier_blocks_and_other_networks() {
        let easiest_target = Network::Mainnet.target_difficulty_limit().to_compact();
        for height in [Height(0), MAINNET_WORK_FLOOR_HEIGHT] {
            assert!(has_sufficient_work(
                &Network::Mainnet,
                height,
                easiest_target
            ));
        }
        let height = MAINNET_WORK_FLOOR_HEIGHT.next().unwrap();
        assert!(!has_sufficient_work(
            &Network::Mainnet,
            height,
            easiest_target
        ));
        for network in [
            Network::new_default_testnet(),
            Network::new_regtest(Default::default()),
        ] {
            assert!(has_sufficient_work(&network, height, easiest_target));
        }
    }

    #[test]
    // kogany: Zcash Mainnet's floor; with `ycash` there is none (see `has_sufficient_work`).
    #[cfg(not(feature = "ycash"))]
    fn mainnet_work_floor_compares_expanded_targets_at_the_boundary() {
        let height = MAINNET_WORK_FLOOR_HEIGHT.next().unwrap();
        let max_target =
            MAINNET_REFERENCE_TARGET.to_expanded().unwrap() * MAINNET_TARGET_MULTIPLIER;
        let easiest_allowed_encoding = max_target.to_compact();
        let easier_encoding = CompactDifficulty::from_le_bytes(
            (u32::from_le_bytes(easiest_allowed_encoding.to_le_bytes()) + 1).to_le_bytes(),
        );

        assert!(has_sufficient_work(
            &Network::Mainnet,
            height,
            MAINNET_REFERENCE_TARGET
        ));
        assert!(has_sufficient_work(
            &Network::Mainnet,
            height,
            easiest_allowed_encoding
        ));
        assert!(!has_sufficient_work(
            &Network::Mainnet,
            height,
            easier_encoding
        ));
        assert!(!has_sufficient_work(
            &Network::Mainnet,
            height,
            CompactDifficulty::from_le_bytes([0; 4]),
        ));
    }

    /// kogany: a Ycash build applies no download work floor on any network, at any height.
    #[test]
    #[cfg(feature = "ycash")]
    fn ycash_networks_have_no_download_work_floor() {
        let height = MAINNET_WORK_FLOOR_HEIGHT.next().unwrap();
        for network in [
            Network::Mainnet,
            Network::new_default_testnet(),
            Network::new_regtest(Default::default()),
        ] {
            let easiest_target = network.target_difficulty_limit().to_compact();
            for height in [Height(0), MAINNET_WORK_FLOOR_HEIGHT, height, Height::MAX] {
                assert!(has_sufficient_work(&network, height, easiest_target));
            }
        }
    }
}
