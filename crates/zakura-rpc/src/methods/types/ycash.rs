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
            ydf::{is_ycash_active, ydf_address, ydf_mandate_end_height, ydf_reward},
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
/// name ycashd compiles in (`strTestnetProfile`; the field is pushed when it is not empty,
/// `ycash6 src/rpc/blockchain.cpp`). `slow` and `legacy` are the shadow-fork magics; every other
/// testnet, including the default `fast` profile and a configured one, is reported as `fast`.
/// Absent on Mainnet and Regtest.
pub fn testnet_profile(network: &Network) -> Option<String> {
    if !network.is_a_test_network() || network.is_regtest() {
        return None;
    }
    Some(
        if network.magic() == magics::TESTNET_SLOW {
            "slow"
        } else if network.magic() == magics::TESTNET_LEGACY {
            "legacy"
        } else {
            "fast"
        }
        .to_string(),
    )
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

/// ycashd's refusal of a block whose data a pruned node deleted: `getblock` answers
/// `RPC_INTERNAL_ERROR` (-32603) with this text (`ycash6 src/rpc/blockchain.cpp:785`, the
/// `fHavePruned && !BLOCK_HAVE_DATA` check), where Zakura answers "Block not found" (-8). The
/// difference matters to lightwalletd-dd, which reads -8 as "beyond the tip" and waits for the
/// block forever (`common/common.go`, `getBlockFromRPC`); -32603 is an error it reports.
pub const PRUNED_BLOCK: &str = "Block not available (pruned data)";

/// Whether the body of a block this node knows was pruned (pruning assessment KP-1): the node
/// prunes, and the block (a best-chain height, or a hash whose header it keeps) is below
/// `pruneheight`. Genesis is never pruned. `false` on any state error, so the caller keeps
/// Zakura's own answer.
pub async fn block_body_pruned<ReadState>(read_state: ReadState, at: HashOrHeight) -> bool
where
    ReadState: ReadStateService,
{
    let Ok(ReadResponse::PruningInfo {
        pruned: true,
        prune_height: Some(lowest),
    }) = read_state.clone().oneshot(ReadRequest::PruningInfo).await
    else {
        return false;
    };
    let height = match at {
        HashOrHeight::Height(h) => h,
        HashOrHeight::Hash(_) => match read_state.oneshot(ReadRequest::BlockHeader(at)).await {
            Ok(ReadResponse::BlockHeader { height, .. }) => height,
            _ => return false,
        },
    };
    height > Height(0) && height < lowest
}

/// The [`ChainWorkCache`] of the genesis block: its own work.
async fn genesis_work<ReadState>(
    read_state: ReadState,
    genesis: block::Hash,
) -> Option<ChainWorkCache>
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

/// The versions of a plain-YEC post-quantum address for a network (`PlainPQAddressVersions`,
/// `ycash6 src/key_io.cpp`, decisions D-Q-20 and D-9): one 3-byte version per scheme, `sqf…`/`sqs…`
/// on Mainnet, `tqf…`/`tqs…` on the testnets, `rqf…`/`rqs…` on Regtest, keyed by ycashd's network
/// name ([`chain_name`]).
pub fn pq_address_versions(
    network: &Network,
) -> &'static kogany_yellowback::codecs::address::PqAddressVersions {
    use kogany_yellowback::codecs::address::{plain_pq_address_versions, PLAIN_PQ_VERSIONS_TEST};
    plain_pq_address_versions(&chain_name(network)).unwrap_or(&PLAIN_PQ_VERSIONS_TEST)
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
/// after the transparent forms (`ycash6 src/key_io.cpp`, D-9): `Base58Check(version || keyHash)`,
/// 35 bytes, one of this network's per-scheme versions and a registered scheme only; the pre-D-9
/// form is refused. A Yellowback `yb…`/`yt…`/`yr…` address is not a destination: ycashd's
/// `validateaddress` answers `isvalid` false for it (N9, `yed_validateaddress` is the call), and
/// so does this.
pub fn decode_pq_address(network: &Network, encoded: &str) -> Option<PqAddress> {
    use kogany_yellowback::codecs::{
        address::{decode_pq, encode_pq},
        script::pq_key_script,
    };

    let versions = pq_address_versions(network);
    let owner = decode_pq(encoded, versions)?;
    // `pq_key_script` refuses an unregistered scheme (`pq::IsKnownScheme`).
    let script = pq_key_script(&owner)?;
    Some(PqAddress {
        address: encode_pq(&owner, versions)?,
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

    // The mandatory YDF is the consensus value `miner_subsidy` takes out (`ydf_reward`, the
    // halving subsidy / 20). It equals `block_subsidy / 20` at every height a Ycash network
    // schedules; on a regtest that configures ZIP 234, `block_subsidy` also carries the
    // reissuance bonus, and a share of it would pay the YDF more than `miner_subsidy` leaves out.
    if height < ydf_mandate_end_height(network) {
        return ydf_reward(network, height);
    }

    let subsidy =
        u64::try_from(i64::from(block_subsidy)).expect("a non-negative amount converts to u64");
    let share = subsidy * DEFAULT_YDF_FEE_PERCENTAGE / 100;

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

/// An insight-explorer address parameter (`getAddressesFromParams`, ycash6 `src/rpc/misc.cpp`):
/// a transparent or plain post-quantum address, or else a YED address (`yb…`/`yt…`/`yr…`, a
/// P2PKH key or a post-quantum key, `yellowback::DecodeAddress`), which names the same index key
/// as its transparent form (S5 `wallet_pq_address`). The YED prefixes differ per network, so
/// each network's are tried.
pub fn insight_address(text: &str) -> Option<transparent::Address> {
    use kogany_yellowback::codecs::{address::decode_any_address, script::Holder};
    use zakura_chain::parameters::NetworkKind;
    if let Ok(address) = text.parse::<transparent::Address>() {
        return Some(address);
    }
    [
        ("main", NetworkKind::Mainnet, NetworkKind::Mainnet),
        ("test", NetworkKind::Testnet, NetworkKind::Testnet),
        ("regtest", NetworkKind::Testnet, NetworkKind::Regtest),
    ]
    .into_iter()
    .find_map(|(id, t_kind, pq_kind)| {
        let params = kogany_yellowback::params::params_for_network(id)?;
        Some(match decode_any_address(text, &params)? {
            Holder::KeyId(key_id) => transparent::Address::from_pub_key_hash(t_kind, key_id),
            Holder::Pq(owner) => transparent::Address::PayToPqKeyHash {
                network_kind: pq_kind,
                scheme: owner.scheme,
                key_hash: owner.hash.0,
            },
        })
    })
}

/// `getblock`'s `chainhistoryroot` (ycash6 `blockToJSON`, `CBlockIndex::hashChainHistoryRoot`,
/// display order; S5 `vault_upgrade.py`): from after the Heartwood activation block until NU5 the
/// header's `blockcommitments` is that root (ZIP 221; `block_commitments` is already in display
/// order), and it is null (zeros) before. Ycash has no NU5 height.
pub fn chain_history_root(
    network: &Network,
    height: Height,
    block_commitments: [u8; 32],
) -> [u8; 32] {
    match NetworkUpgrade::Heartwood.activation_height(network) {
        Some(heartwood) if height > heartwood && is_pre_nu5(network, height) => block_commitments,
        _ => [0; 32],
    }
}

/// `z_gettreestate`'s `finalState` as ycashd writes it (kogany W9-c finding 4): the
/// incremental-merkle-tree serialization (`Optional left`, `Optional right`, `CompactSize n`,
/// `n x Optional parent`) without trailing empty parents. ycashd grows its tree append by append,
/// so the topmost parent it holds is never empty; Zakura rebuilds the tree from a frontier with
/// every level present. Bytes that do not parse are returned unchanged.
pub fn trim_tree_parents(bytes: Vec<u8>) -> Vec<u8> {
    fn optional(b: &[u8], at: usize) -> Option<usize> {
        match b.get(at)? {
            0 => Some(at + 1),
            1 if b.len() >= at + 33 => Some(at + 33),
            _ => None,
        }
    }
    let parse = || -> Option<Vec<u8>> {
        let after_left = optional(&bytes, 0)?;
        let after_right = optional(&bytes, after_left)?;
        let count = usize::from(*bytes.get(after_right)?);
        if count >= 0xfd {
            return None;
        }
        let mut parents = Vec::with_capacity(count);
        let mut at = after_right + 1;
        for _ in 0..count {
            let next = optional(&bytes, at)?;
            parents.push(bytes.get(at..next)?);
            at = next;
        }
        if at != bytes.len() {
            return None;
        }
        while parents.last().is_some_and(|p| p == &[0]) {
            parents.pop();
        }
        let mut out = bytes.get(..after_right)?.to_vec();
        out.push(u8::try_from(parents.len()).ok()?);
        parents.iter().for_each(|p| out.extend_from_slice(p));
        Some(out)
    };
    parse().unwrap_or(bytes)
}

/// Puts `getaddressutxos` results in ycashd's order. Zakura returns them in chain order (height,
/// transaction index, output index); ycashd reads each requested address's entries from its
/// address-unspent index in key order, `(type, hashBytes, txhash, index)` with `txhash` in its
/// internal byte order and `index` little-endian (`ycash6 src/addressindex.h`,
/// `CAddressUnspentKey::Serialize`), concatenates the addresses in request order, then sorts by
/// block height (`ycash6 src/rpc/misc.cpp`, `getaddressutxos`). That sort is `std::sort`, so the
/// order inside one height is the index order only as far as the sort keeps it; this applies the
/// stable form of it, which is what ycashd returns for the small sets a wallet asks for.
///
/// `request_addresses` is the request's address list, in order; an address listed twice ranks at
/// its first position (Zakura answers it once, ycashd twice).
pub fn order_address_utxos_as_ycashd(
    utxos: &mut [crate::methods::Utxo],
    request_addresses: &[transparent::Address],
) {
    let rank = |address: &transparent::Address| {
        request_addresses
            .iter()
            .position(|requested| requested == address)
            .unwrap_or(request_addresses.len())
    };
    utxos.sort_by_cached_key(|utxo| {
        (
            utxo.height(),
            rank(utxo.address()),
            utxo.txid().0,
            utxo.output_index().index().to_le_bytes(),
        )
    });
}

#[cfg(test)]
mod tests;
