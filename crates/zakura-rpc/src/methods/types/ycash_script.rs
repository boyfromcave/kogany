// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Ycash (kogany W7-e): the `type`, `reqSigs` and `addresses` of a verbose `scriptPubKey`
//! (`getrawtransaction 1`, `getblock 2`, `gettxout`) as ycashd writes them
//! (`ycash6 src/rpc/rawtransaction.cpp:45-69` `ScriptPubKeyToJSON` over
//! `src/script/standard.cpp` `Solver`, `ExtractDestinations`, `GetTxnOutputType`).
//!
//! Zakura's shape differs on the Ycash script kinds: the vault primitive's templates
//! (`vault`, `vaultintent`), the post-quantum key hash (`pqpubkeyhash`, with its `sqf…`/`sqs…`,
//! `tqf…`/`tqs…` or `rqf…`/`rqs…` address, D-9) and channel (`pqchannel`), and on two stock ones: a
//! bare multisig lists its keys' P2PKH addresses with `reqSigs` the threshold, and a P2PK lists
//! its key's.

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

/// `CScript::IsUnspendable` (`ycash6 src/script/script.h`): an `OP_RETURN` script or one above
/// `MAX_SCRIPT_SIZE` (10,000 bytes). ycashd's coins view never holds such an output
/// (`CCoins::ClearUnspendable`), so `gettxout` answers null for it.
pub(crate) fn is_unspendable(script: &transparent::Script) -> bool {
    let bytes = script.as_raw_bytes();
    bytes.first() == Some(&0x6a) || bytes.len() > 10_000
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
        Destination::PqKeyHash(id) => kogany_yellowback::codecs::address::encode_pq(
            &kogany_vault::PqOwner {
                scheme: id.scheme,
                hash: kogany_vault::Hash32(id.key_hash),
            },
            super::ycash::pq_address_versions(network),
        )?,
    })
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

/// ycashd's `ScriptToAsmStr(script, false)` (`ycash6 src/core_write.cpp:73-113`), the `asm` of a
/// `scriptPubKey`, with ycashd's opcode names (`src/script/script.cpp` `GetOpName`), including
/// the Ycash opcodes `OP_CHECKSETSIG`, `OP_CHECKSETDORMANT` and `OP_CHECKPQSIG` that Zakura's
/// disassembler stops at (`[error]`).
pub(crate) fn script_to_asm(bytes: &[u8]) -> String {
    let mut words: Vec<String> = Vec::new();
    let mut pc = 0;
    while pc < bytes.len() {
        let opcode = bytes[pc];
        pc += 1;
        if opcode <= 0x4e {
            // A push: the length is the opcode itself or the next 1, 2 or 4 bytes.
            let width = match opcode {
                0x4c => 1,
                0x4d => 2,
                0x4e => 4,
                _ => 0,
            };
            let len = if width == 0 {
                usize::from(opcode)
            } else {
                let Some(field) = bytes.get(pc..pc + width) else {
                    words.push("[error]".to_owned());
                    break;
                };
                pc += width;
                field
                    .iter()
                    .rev()
                    .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
            };
            let Some(data) = pc.checked_add(len).and_then(|end| bytes.get(pc..end)) else {
                words.push("[error]".to_owned());
                break;
            };
            pc += len;
            words.push(if data.len() <= 4 {
                script_num(data).to_string()
            } else {
                hex::encode(data)
            });
        } else {
            words.push(op_name(opcode).to_owned());
        }
    }
    words.join(" ")
}

/// `CScriptNum(vch, false).getint()` for a push of at most 4 bytes: little-endian, sign bit in
/// the last byte.
fn script_num(data: &[u8]) -> i64 {
    let Some((&last, _)) = data.split_last() else {
        return 0;
    };
    let mut value: i64 = 0;
    for (i, byte) in data.iter().enumerate() {
        value |= i64::from(*byte) << (8 * i);
    }
    if last & 0x80 != 0 {
        -(value & !(0x80i64 << (8 * (data.len() - 1))))
    } else {
        value
    }
}

/// `GetOpName` for a non-push opcode.
fn op_name(opcode: u8) -> &'static str {
    const NAMES: [&str; 0xba - 0x4f] = [
        "-1",
        "OP_RESERVED",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "10",
        "11",
        "12",
        "13",
        "14",
        "15",
        "16",
        "OP_NOP",
        "OP_VER",
        "OP_IF",
        "OP_NOTIF",
        "OP_VERIF",
        "OP_VERNOTIF",
        "OP_ELSE",
        "OP_ENDIF",
        "OP_VERIFY",
        "OP_RETURN",
        "OP_TOALTSTACK",
        "OP_FROMALTSTACK",
        "OP_2DROP",
        "OP_2DUP",
        "OP_3DUP",
        "OP_2OVER",
        "OP_2ROT",
        "OP_2SWAP",
        "OP_IFDUP",
        "OP_DEPTH",
        "OP_DROP",
        "OP_DUP",
        "OP_NIP",
        "OP_OVER",
        "OP_PICK",
        "OP_ROLL",
        "OP_ROT",
        "OP_SWAP",
        "OP_TUCK",
        "OP_CAT",
        "OP_SUBSTR",
        "OP_LEFT",
        "OP_RIGHT",
        "OP_SIZE",
        "OP_INVERT",
        "OP_AND",
        "OP_OR",
        "OP_XOR",
        "OP_EQUAL",
        "OP_EQUALVERIFY",
        "OP_RESERVED1",
        "OP_RESERVED2",
        "OP_1ADD",
        "OP_1SUB",
        "OP_2MUL",
        "OP_2DIV",
        "OP_NEGATE",
        "OP_ABS",
        "OP_NOT",
        "OP_0NOTEQUAL",
        "OP_ADD",
        "OP_SUB",
        "OP_MUL",
        "OP_DIV",
        "OP_MOD",
        "OP_LSHIFT",
        "OP_RSHIFT",
        "OP_BOOLAND",
        "OP_BOOLOR",
        "OP_NUMEQUAL",
        "OP_NUMEQUALVERIFY",
        "OP_NUMNOTEQUAL",
        "OP_LESSTHAN",
        "OP_GREATERTHAN",
        "OP_LESSTHANOREQUAL",
        "OP_GREATERTHANOREQUAL",
        "OP_MIN",
        "OP_MAX",
        "OP_WITHIN",
        "OP_RIPEMD160",
        "OP_SHA1",
        "OP_SHA256",
        "OP_HASH160",
        "OP_HASH256",
        "OP_CODESEPARATOR",
        "OP_CHECKSIG",
        "OP_CHECKSIGVERIFY",
        "OP_CHECKMULTISIG",
        "OP_CHECKMULTISIGVERIFY",
        "OP_NOP1",
        "OP_NOP2",
        "OP_NOP3",
        "OP_NOP4",
        "OP_NOP5",
        "OP_NOP6",
        "OP_NOP7",
        "OP_NOP8",
        "OP_NOP9",
        "OP_NOP10",
    ];
    match opcode {
        0x4f..=0xb9 => NAMES[usize::from(opcode - 0x4f)],
        0xc0 => "OP_CHECKSETSIG",
        0xc1 => "OP_CHECKSETDORMANT",
        0xc2 => "OP_CHECKPQSIG",
        0xff => "OP_INVALIDOPCODE",
        _ => "OP_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asm_names_the_ycash_opcodes() {
        let pqpkh = [&[0x20][..], &[0xab; 32], &[0x51, 0xc2]].concat();
        assert_eq!(
            script_to_asm(&pqpkh),
            format!("{} 1 OP_CHECKPQSIG", "ab".repeat(32))
        );
        assert_eq!(
            script_to_asm(&[0x76, 0xa9, 0x01, 0x81, 0x02, 0xff, 0x00, 0xb2, 0xc0, 0xc1, 0xbb]),
            "OP_DUP OP_HASH160 -1 255 OP_NOP3 OP_CHECKSETSIG OP_CHECKSETDORMANT OP_UNKNOWN"
        );
        assert_eq!(script_to_asm(&[0x00, 0x4f, 0x60]), "0 -1 16");
        assert_eq!(script_to_asm(&[0x51, 0x05, 0x01]), "1 [error]");
        assert_eq!(script_num(&[0x04, 0x03, 0x02, 0x81]), -0x0102_0304);
    }
}
