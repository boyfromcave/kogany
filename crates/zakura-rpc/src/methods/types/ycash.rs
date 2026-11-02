//! Ycash answers for the stock mining and chain RPCs (kogany W1-Y6), compiled under the `ycash`
//! feature. Each function is called from one hook in an upstream method body, so the upstream
//! code stays as it is and the Ycash values live here.
//!
//! Every value cites the ycashd line it mirrors: `ycash6` at `65cb4ae0f` (`vaults/kogany-compat`
//! = `upgrade/vault`).

use std::sync::Mutex;

use tower::ServiceExt;
use zakura_chain::{
    amount::{Amount, NonNegative},
    block::{self, Height},
    parameters::{
        subsidy::founders_reward,
        ycash::{
            magics,
            ydf::{is_ycash_active, ydf_address, ydf_mandate_end_height, YDF_DIVISOR},
        },
        Network, NetworkUpgrade,
    },
    transparent,
    work::difficulty::{CompactDifficulty, ParameterDifficulty, U256},
};
use zakura_state::{HashOrHeight, ReadRequest, ReadResponse, ReadState as ReadStateService};

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

/// The `testnetprofile` field of `getblockchaininfo`: on the Ycash testnets only, the profile
/// name ycashd compiles in (`strTestnetProfile`, `ycash6 src/chainparams.cpp:639,661`; the field
/// is pushed when it is not empty, `src/rpc/blockchain.cpp:1688-1689`). The `slow` profile is the
/// testnet with its magic ([`Network::new_ycash_testnet_slow`]); every other testnet, the default
/// one and a configured one, is the `fast` profile, as for its default port. kogany drops the
/// `legacy` profile (decision K-10). Absent on Mainnet and Regtest.
pub fn testnet_profile(network: &Network) -> Option<String> {
    if !network.is_a_test_network() || network.is_regtest() {
        return None;
    }
    Some(if network.magic() == magics::TESTNET_SLOW { "slow" } else { "fast" }.to_string())
}

/// The cumulative work cached by [`chain_work`]: the network's genesis hash, and the work from
/// genesis through the block `hash` at `height` (ycashd's `CBlockIndex::nChainWork`).
#[derive(Clone, Copy, Debug)]
struct ChainWorkCache {
    genesis: block::Hash,
    height: Height,
    hash: block::Hash,
    work: U256,
}

/// The process's [`ChainWorkCache`]. One node serves one network; the genesis hash keys it anyway,
/// so tests on several networks in one process never mix their values.
static CHAIN_WORK: Mutex<Option<ChainWorkCache>> = Mutex::new(None);

/// The most header batches (of `MAX_FIND_BLOCK_HEADERS_RESULTS`, 160) [`chain_work`] reads in one
/// call: about 160,000 headers. A longer catch-up, the first calls on a synced mainnet node,
/// continues across calls, and the field is omitted until the cache reaches the tip.
const CHAIN_WORK_BATCHES_PER_CALL: usize = 1_000;

/// The `chainwork` field of `getblockchaininfo`: the total work of the best chain through the
/// tip, as ycashd's 64-digit hex string (`chainActive.Tip()->nChainWork.GetHex()`,
/// `ycash6 src/rpc/blockchain.cpp:1696`). Zakura stores no cumulative work (it reports `0`), so
/// it is summed here from the headers, each block's work as ycashd's `GetBlockProof`
/// (`2^256 / (target + 1)`, [`CompactDifficulty::to_work`]), and cached: a call reads only the
/// headers above the cached block, and starts again from genesis when a reorganisation has left
/// the cached block off the best chain.
///
/// `None` (the field is omitted) when the cache could not reach `tip` in this call: a long
/// catch-up, a state error, or a tip that moved during the call.
pub async fn chain_work<ReadState>(
    read_state: ReadState,
    network: &Network,
    tip_height: Height,
    tip_hash: block::Hash,
) -> Option<String>
where
    ReadState: ReadStateService,
{
    let genesis = network.genesis_hash();
    let cached = (*CHAIN_WORK.lock().ok()?).filter(|cache| cache.genesis == genesis);

    let mut cache = match cached {
        Some(cache) if cache.height <= tip_height => cache,
        _ => genesis_work(read_state.clone(), genesis).await?,
    };

    for _ in 0..CHAIN_WORK_BATCHES_PER_CALL {
        if cache.hash == tip_hash {
            break;
        }
        let response = read_state
            .clone()
            .oneshot(ReadRequest::FindBlockHeaders {
                known_blocks: vec![cache.hash],
                stop: Some(tip_hash),
            })
            .await
            .ok()?;
        let ReadResponse::BlockHeaders(headers) = response else {
            return None;
        };
        if headers.is_empty() {
            return None;
        }
        // An intersection other than the cached block (a reorganisation dropped it) answers
        // from another height: start again from genesis.
        if headers[0].header.previous_block_hash != cache.hash {
            cache = genesis_work(read_state.clone(), genesis).await?;
            continue;
        }
        for counted in &headers {
            let header = &counted.header;
            if header.previous_block_hash != cache.hash {
                return None;
            }
            let work = header.difficulty_threshold.to_work()?.as_u256();
            cache = ChainWorkCache {
                genesis,
                height: (cache.height + 1)?,
                hash: header.hash(),
                work: cache.work.checked_add(work)?,
            };
        }
    }

    if let Ok(mut slot) = CHAIN_WORK.lock() {
        *slot = Some(cache);
    }

    (cache.hash == tip_hash && cache.height == tip_height).then(|| format!("{:064x}", cache.work))
}

/// The [`ChainWorkCache`] of the genesis block: its own work.
async fn genesis_work<ReadState>(read_state: ReadState, genesis: block::Hash) -> Option<ChainWorkCache>
where
    ReadState: ReadStateService,
{
    let response = read_state
        .oneshot(ReadRequest::BlockHeader(HashOrHeight::Height(Height(0))))
        .await
        .ok()?;
    let ReadResponse::BlockHeader { header, hash, .. } = response else {
        return None;
    };
    (hash == genesis).then_some(())?;
    Some(ChainWorkCache {
        genesis,
        height: Height(0),
        hash,
        work: header.difficulty_threshold.to_work()?.as_u256(),
    })
}

/// The version bytes of a plain-YEC post-quantum address for a network
/// (`PlainPQAddressVersion`, `ycash6 src/key_io.cpp:25-31`, decision D-Q-20): `0x4DD9` `sq…` on
/// Mainnet, `0x4F61` `tq…` on the testnets, `0x4C51` `rq…` on Regtest, keyed by ycashd's network
/// name ([`chain_name`]).
pub fn pq_address_version(network: &Network) -> [u8; 2] {
    match chain_name(network).as_str() {
        "main" => [0x4D, 0xD9],
        "regtest" => [0x4C, 0x51],
        _ => [0x4F, 0x61],
    }
}

/// A plain-YEC post-quantum address (`CPQKeyID`) as `validateaddress` describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqAddress {
    /// The address, re-encoded (`EncodeDestination`).
    pub address: String,
    /// The hex TX_PQPKH script, `<keyHash:32> OP_<scheme> OP_CHECKPQSIG` (`GetScriptForPQKey`,
    /// `ycash6 src/script/standard.cpp:336-340`).
    pub script_pub_key: String,
    /// The scheme: 1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512 (`pqscheme`).
    pub scheme: u8,
    /// The 32-byte key hash as pushed in the script, in hex (`pqkeyhash`).
    pub key_hash: String,
}

/// Decodes a plain-YEC post-quantum address of `network`, as ycashd's `DecodeDestination` does
/// after the transparent forms (`ycash6 src/key_io.cpp:318-339`): `Base58Check(version ||
/// scheme || keyHash)`, 35 bytes, this network's version and a registered scheme only. A
/// Yellowback `yb…`/`yt…`/`yr…` address is not a destination: ycashd's `validateaddress` answers
/// `isvalid` false for it (N9, `yed_validateaddress` is the call), and so does this.
pub fn decode_pq_address(network: &Network, encoded: &str) -> Option<PqAddress> {
    use kogany_yellowback::codecs::{
        base58::{decode_base58_check, encode_base58_check},
        script::pq_key_script,
    };

    let data = decode_base58_check(encoded)?;
    let version = pq_address_version(network);
    if data.len() != version.len() + 1 + 32 || data[..2] != version {
        return None;
    }
    let owner = kogany_vault::PqOwner {
        scheme: data[2],
        hash: kogany_vault::Hash32::from_slice(&data[3..])?,
    };
    // `pq_key_script` refuses an unregistered scheme (`pq::IsKnownScheme`).
    let script = pq_key_script(&owner)?;
    Some(PqAddress {
        address: encode_base58_check(&data),
        script_pub_key: hex::encode(script),
        scheme: owner.scheme,
        key_hash: hex::encode(owner.hash.0),
    })
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
