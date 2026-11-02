// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (kogany W7-e): the `type`, `reqSigs` and `addresses` of a verbose `scriptPubKey`
//! (`getrawtransaction 1`, `getblock 2`, `gettxout`) as ycashd writes them
//! (`ycash6 src/rpc/rawtransaction.cpp:45-69` `ScriptPubKeyToJSON` over
//! `src/script/standard.cpp` `Solver`, `ExtractDestinations`, `GetTxnOutputType`).
//!
//! Zakura's shape differs on the Ycash script kinds: the vault primitive's templates
//! (`vault`, `vaultintent`), the post-quantum key hash (`pqpubkeyhash`, with its `sq…`/`tq…`/`rq…`
//! address) and channel (`pqchannel`), and on two stock ones: a bare multisig lists its keys'
//! P2PKH addresses with `reqSigs` the threshold, and a P2PK lists its key's.

use zakura_chain::{
    parameters::Network,
    transparent::{self, Destination},
};

/// The `scriptPubKey` fields ycashd derives from the script: `(reqSigs, type, addresses)`.
/// `zakura_type` is the type Zakura's solver gave (`pubkeyhash`, `scripthash`, `multisig`,
/// `nulldata`, `pubkey` or `nonstandard`).
pub(crate) fn script_pub_key_fields(
    script: &transparent::Script,
    zakura_type: String,
    network: &Network,
) -> (Option<u32>, String, Option<Vec<String>>) {
    let bytes = script.as_raw_bytes();
    let kind = match zakura_type.as_str() {
        "nonstandard" => ycash_kind(bytes).unwrap_or("nonstandard").to_owned(),
        _ => zakura_type,
    };

    // ExtractDestinations: a multisig's valid keys, else the one destination.
    if kind == "multisig" {
        let Some((required, keys)) = multisig(bytes) else {
            return (None, kind, None);
        };
        let addresses: Vec<String> = keys
            .iter()
            .filter(|key| valid_pubkey_size(key))
            .map(|key| {
                transparent::Address::from_pub_key_hash(
                    network.t_addr_kind(),
                    kogany_vault::template::hash160(key),
                )
                .to_string()
            })
            .collect();
        if addresses.is_empty() {
            return (None, kind, None);
        }
        return (Some(u32::from(required)), kind, Some(addresses));
    }
    match script
        .destination()
        .and_then(|d| encode_destination(d, network))
    {
        Some(address) if kind != "nulldata" => (Some(1), kind, Some(vec![address])),
        _ => (None, kind, None),
    }
}

/// The Ycash `Solver` kinds Zakura's solver does not know.
fn ycash_kind(bytes: &[u8]) -> Option<&'static str> {
    if transparent::Script::new(bytes).pq_key_id().is_some() {
        return Some("pqpubkeyhash");
    }
    if kogany_yellowback::codecs::script::match_pq_channel(bytes).is_some() {
        return Some("pqchannel");
    }
    if kogany_vault::template::parse_vault(bytes).is_some() {
        return Some("vault");
    }
    if kogany_vault::template::parse_intent(bytes).is_some() {
        return Some("vaultintent");
    }
    None
}

/// `KeyIO::EncodeDestination`; `None` where ycashd encodes `""` (an unregistered post-quantum
/// scheme), which then lists no address.
fn encode_destination(destination: Destination, network: &Network) -> Option<String> {
    Some(match destination {
        Destination::PubKeyHash(hash) => {
            transparent::Address::from_pub_key_hash(network.t_addr_kind(), hash).to_string()
        }
        Destination::ScriptHash(hash) => {
            transparent::Address::from_script_hash(network.t_addr_kind(), hash).to_string()
        }
        Destination::PqKeyHash(id) => {
            if !kogany_vault::template::is_known_pq_scheme(id.scheme) {
                return None;
            }
            let mut data = pq_address_version(network).to_vec();
            data.push(id.scheme);
            data.extend_from_slice(&id.key_hash);
            kogany_yellowback::codecs::base58::encode_base58_check(&data)
        }
    })
}

/// `PlainPQAddressVersion` (`ycash6 src/key_io.cpp:25-31`): `sq…` on Mainnet, `tq…` on the
/// testnets, `rq…` on Regtest.
fn pq_address_version(network: &Network) -> [u8; 2] {
    if network.is_regtest() {
        [0x4C, 0x51]
    } else if network.is_a_test_network() {
        [0x4F, 0x61]
    } else {
        [0x4D, 0xD9]
    }
}

/// `CPubKey::ValidSize`.
fn valid_pubkey_size(key: &[u8]) -> bool {
    match key.first() {
        Some(2 | 3) => key.len() == 33,
        Some(4 | 6 | 7) => key.len() == 65,
        _ => false,
    }
}

/// `MatchMultisig`: `OP_m <key>… OP_n OP_CHECKMULTISIG`, the threshold and the keys.
fn multisig(bytes: &[u8]) -> Option<(u8, Vec<&[u8]>)> {
    let (&first, rest) = bytes.split_first()?;
    let (&last, rest) = rest.split_last()?;
    let (&n_op, mut keys_part) = rest.split_last()?;
    if last != 0xae || !(0x51..=0x60).contains(&first) || !(0x51..=0x60).contains(&n_op) {
        return None;
    }
    let mut keys = Vec::new();
    while let Some((&len, tail)) = keys_part.split_first() {
        let len = usize::from(len);
        if !(33..=65).contains(&len) || tail.len() < len {
            return None;
        }
        keys.push(&tail[..len]);
        keys_part = &tail[len..];
    }
    let required = first - 0x50;
    (usize::from(n_op - 0x50) == keys.len() && usize::from(required) <= keys.len())
        .then_some((required, keys))
}
