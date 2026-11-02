//! Ycash answers for the stock mining and chain RPCs (kogany W1-Y6), compiled under the `ycash`
//! feature. Each function is called from one hook in an upstream method body, so the upstream
//! code stays as it is and the Ycash values live here.
//!
//! Every value cites the ycashd line it mirrors: `ycash6` at `65cb4ae0f` (`vaults/kogany-compat`
//! = `upgrade/vault`).

use zakura_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::{
        subsidy::founders_reward,
        ycash::ydf::{is_ycash_active, ydf_address, ydf_mandate_end_height, YDF_DIVISOR},
        Network, NetworkUpgrade,
    },
    transparent,
    work::difficulty::{CompactDifficulty, ParameterDifficulty},
};

/// The largest YDF share, in percent, a miner may pay voluntarily after the mandate ends, and the
/// default share ycashd's miner pays then (`MAX_YDF_FEE_PERCENTAGE` and
/// `DEFAULT_YDF_FEE_PERCENTAGE`, `ycash6 src/consensus/consensus.h:44-46`). kogany has no `-ydf`
/// setting yet, so it always pays the default, as a ycashd started without `-ydf` does.
pub const DEFAULT_YDF_FEE_PERCENTAGE: u64 = 5;

/// The `chain` field of `getblockchaininfo` and `getmininginfo`: ycashd's `strNetworkID`, which is
/// `regtest` on Regtest (`ycash6 src/chainparams.cpp`, `CRegTestParams`). Zakura reports the BIP70
/// name, `test`, there; yolo picks its Equihash parameters from this field
/// (`yolo src/equihash.rs:23-28`).
pub fn chain_name(network: &Network) -> String {
    if network.is_regtest() {
        "regtest".to_string()
    } else {
        network.bip70_network_name()
    }
}

/// The `testnet` field of `getinfo`: true on the Ycash testnets only, false on Regtest
/// (`TestnetToBeDeprecatedFieldRPC`, `ycash6 src/chainparams.cpp`).
pub fn is_testnet_field(network: &Network) -> bool {
    network.is_a_test_network() && !network.is_regtest()
}

/// The founders' or YDF share of the block subsidy that ycashd's miner pays at `height`, in the
/// order of `SetFoundersRewardAndGetMinerValue` (`ycash6 src/miner.cpp:119-157`):
///
/// - before the Ycash upgrade, the inherited Zcash founders' reward (`subsidy / 5`, zero after
///   the founders' schedule), which Zakura already computes;
/// - from the Ycash upgrade until the mandate ends, the mandatory YDF, `subsidy / 20`;
/// - after the mandate, the optional YDF, `subsidy * DEFAULT_YDF_FEE_PERCENTAGE / 100`.
///
/// `getblocksubsidy`'s `founders` field reports the same value (`ycash6 src/rpc/mining.cpp:963-983`).
pub fn founders_share(
    network: &Network,
    height: Height,
    block_subsidy: Amount<NonNegative>,
) -> Amount<NonNegative> {
    if !is_ycash_active(network, height) {
        return founders_reward(network, height);
    }

    let subsidy =
        u64::try_from(i64::from(block_subsidy)).expect("a non-negative amount converts to u64");
    let share = if height < ydf_mandate_end_height(network) {
        subsidy / YDF_DIVISOR
    } else {
        subsidy * DEFAULT_YDF_FEE_PERCENTAGE / 100
    };

    i64::try_from(share)
        .ok()
        .and_then(|share| Amount::try_from(share).ok())
        .expect("a share of a valid block subsidy is a valid amount")
}

/// The share of [`founders_share`] that the consensus rules do not already take out of Zakura's
/// `miner_subsidy`: the optional post-mandate YDF. `miner_subsidy` subtracts the founders' reward
/// and the mandatory YDF (W1-Y3), so the coinbase builder subtracts only this.
pub fn optional_ydf_share(
    network: &Network,
    height: Height,
    block_subsidy: Amount<NonNegative>,
) -> Amount<NonNegative> {
    if !is_ycash_active(network, height) || height < ydf_mandate_end_height(network) {
        return Amount::zero();
    }
    founders_share(network, height, block_subsidy)
}

/// The `miner` and `founders` fields of `getblocksubsidy` (`ycash6 src/rpc/mining.cpp:963-987`),
/// from Zakura's `miner_subsidy` and `founders_reward`: from the Ycash upgrade on, `founders` is
/// the YDF share [`founders_share`] and `miner` excludes the optional post-mandate YDF too.
/// Before the upgrade Zakura's values are ycashd's.
pub fn subsidy_fields(
    network: &Network,
    height: Height,
    block_subsidy: Amount<NonNegative>,
    miner: Amount<NonNegative>,
    founders: Amount<NonNegative>,
) -> Result<(Amount<NonNegative>, Amount<NonNegative>), zakura_chain::amount::Error> {
    if !is_ycash_active(network, height) {
        return Ok((miner, founders));
    }
    Ok((
        (miner - optional_ydf_share(network, height, block_subsidy))?,
        founders_share(network, height, block_subsidy),
    ))
}

/// The coinbase output ycashd's miner adds for the YDF at `height`, `None` when it adds none
/// (`ycash6 src/miner.cpp:136-148`): the share of [`founders_share`] to [`ydf_address`], from the
/// Ycash upgrade on. Before the upgrade Zakura has no founders' output to build, and none is
/// needed: every Ycash network's pre-fork history is a synced chain, never a template.
pub fn ydf_output(
    network: &Network,
    height: Height,
    block_subsidy: Amount<NonNegative>,
) -> Option<(Amount<NonNegative>, transparent::Address)> {
    if !is_ycash_active(network, height) {
        return None;
    }
    let amount = founders_share(network, height, block_subsidy);
    if amount == Amount::<NonNegative>::zero() {
        return None;
    }
    Some((amount, ydf_address(network, height)?))
}

/// The `foundersreward` field of `getblocktemplate`'s `coinbasetxn`, in zatoshis, when ycashd
/// sends it (`ycash6 src/rpc/mining.cpp:773-783`): the founders' reward before the Ycash upgrade
/// and the mandatory YDF until the mandate ends; absent after the mandate, when the YDF is
/// optional.
pub fn template_founders_reward(
    network: &Network,
    height: Height,
    block_subsidy: Amount<NonNegative>,
) -> Option<Amount<NonNegative>> {
    if is_ycash_active(network, height) && height >= ydf_mandate_end_height(network) {
        return None;
    }
    let reward = founders_share(network, height, block_subsidy);
    (is_ycash_active(network, height) || reward != Amount::<NonNegative>::zero()).then_some(reward)
}

/// The difficulty of the next block as ycashd computes it: on Regtest always the proof-of-work
/// limit, because ycashd's regtest turns the adjustment off in both directions
/// (`nPowMaxAdjustDown = nPowMaxAdjustUp = 0`, `ycash6 src/chainparams.cpp:719-720`), so the
/// averaging window's mean target stays the genesis target. Zakura disables proof of work on
/// Regtest and keeps adjusting, which ycashd refuses as `bad-diffbits`. Elsewhere `computed`.
pub fn expected_difficulty(network: &Network, computed: CompactDifficulty) -> CompactDifficulty {
    if network.is_regtest() {
        network.target_difficulty_limit().to_compact()
    } else {
        computed
    }
}

/// True if `height` is below NU5. From Heartwood until NU5 the header's `hashBlockCommitments`
/// is the chain history root alone (ZIP 221); Ycash has no NU5 height, so every Ycash template
/// takes this form (`ycash6 src/miner.cpp`, `src/rpc/mining.cpp:374-391`, where `authdataroot`
/// and `defaultroots.blockcommitmentshash` are NU5-only).
pub fn is_pre_nu5(network: &Network, height: Height) -> bool {
    NetworkUpgrade::current(network, height) < NetworkUpgrade::Nu5
}

#[cfg(test)]
mod tests;
