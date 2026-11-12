//! Transparent Address types.

use crate::serialization::ZcashReader;
use std::io::Read as _;
use std::{fmt, io};

use crate::{
    parameters::NetworkKind,
    serialization::{SerializationError, ZcashDeserialize, ZcashSerialize},
    transparent::{opcodes::OpCode, Script},
};

#[cfg(test)]
use proptest::prelude::*;
use zcash_address::{ToAddress, ZcashAddress};
use zcash_transparent::address::TransparentAddress;

/// Transparent Zcash Addresses
///
/// In Bitcoin a single byte is used for the version field identifying
/// the address type. In Zcash two bytes are used. For addresses on
/// the production network, this and the encoded length cause the first
/// two characters of the Base58Check encoding to be fixed as "t3" for
/// P2SH addresses, and as "t1" for P2PKH addresses. (This does not
/// imply that a transparent Zcash address can be parsed identically
/// to a Bitcoin address just by removing the "t".)
///
/// <https://zips.z.cash/protocol/protocol.pdf#transparentaddrencoding>
// TODO Remove this type and move to `TransparentAddress` in `zcash-transparent`.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub enum Address {
    /// P2SH (Pay to Script Hash) addresses
    PayToScriptHash {
        /// Production, test, or other network
        network_kind: NetworkKind,
        /// 20 bytes specifying a script hash.
        script_hash: [u8; 20],
    },

    /// P2PKH (Pay to Public Key Hash) addresses
    PayToPublicKeyHash {
        /// Production, test, or other network
        network_kind: NetworkKind,
        /// 20 bytes specifying a public key hash, which is a RIPEMD-160
        /// hash of a SHA-256 hash of a compressed ECDSA key encoding.
        pub_key_hash: [u8; 20],
    },

    /// Transparent-Source-Only Address.
    ///
    /// <https://zips.z.cash/zip-0320.html>
    Tex {
        /// Production, test, or other network
        network_kind: NetworkKind,
        /// 20 bytes specifying the validating key hash.
        validating_key_hash: [u8; 20],
    },

    /// Ycash (kogany W7-b): a post-quantum TX_PQPKH key (ycash6 `CPQKeyID`), the plain-YEC
    /// address (D-Q-20, D-9): `Base58Check(version ‖ keyHash)`, one 3-byte version per network
    /// and scheme (`sqf…`/`sqs…`, `tqf…`/`tqs…`, `rqf…`/`rqs…`). The address index keys it by
    /// `Hash160(scheme ‖ keyHash)` ([`Address::hash_bytes`], ycash6 `CScript::AddressHash`).
    #[cfg(feature = "ycash")]
    PayToPqKeyHash {
        /// Production, test, or other network
        network_kind: NetworkKind,
        /// The scheme byte (1 = SLH-DSA-SHA2-128s, 2 = FN-DSA-512).
        scheme: u8,
        /// `SHA256(scheme ‖ pk)`.
        key_hash: [u8; 32],
    },
}

/// Ycash (kogany): `PlainPQAddressVersions` (ycash6 `src/key_io.cpp`, D-Q-20, D-9): one 3-byte
/// version per scheme, `sqf…`/`sqs…` on Mainnet, `tqf…`/`tqs…` on the testnets, `rqf…`/`rqs…` on
/// Regtest. The one table both directions read (kogany-yellowback `codecs::address`).
#[cfg(feature = "ycash")]
pub(crate) fn plain_pq_address_versions(
    network_kind: NetworkKind,
) -> &'static kogany_yellowback::codecs::address::PqAddressVersions {
    use kogany_yellowback::codecs::address::{
        PLAIN_PQ_VERSIONS_MAIN, PLAIN_PQ_VERSIONS_REGTEST, PLAIN_PQ_VERSIONS_TEST,
    };
    match network_kind {
        NetworkKind::Mainnet => &PLAIN_PQ_VERSIONS_MAIN,
        NetworkKind::Testnet => &PLAIN_PQ_VERSIONS_TEST,
        NetworkKind::Regtest => &PLAIN_PQ_VERSIONS_REGTEST,
    }
}

/// Ycash (kogany): a plain-YEC post-quantum address's Base58Check payload (`version ‖ keyHash`,
/// 35 bytes, D-9), as ycash6 `DecodeDestination` reads it; `None` for anything else, the pre-D-9
/// form (`2-byte version ‖ scheme ‖ keyHash`) among it.
#[cfg(feature = "ycash")]
fn decode_plain_pq(data: &[u8]) -> Option<Address> {
    use kogany_yellowback::codecs::address::decode_pq_data;
    [
        NetworkKind::Mainnet,
        NetworkKind::Testnet,
        NetworkKind::Regtest,
    ]
    .into_iter()
    .find_map(|network_kind| {
        let owner = decode_pq_data(data, plain_pq_address_versions(network_kind))?;
        Some(Address::PayToPqKeyHash {
            network_kind,
            scheme: owner.scheme,
            key_hash: owner.hash.0,
        })
    })
}

/// Ycash (kogany): the length of a transparent (P2PKH/P2SH) Base58Check payload, `version:2 ‖
/// hash:20`. ycashd's `DecodeDestination` refuses any other length, so a payload that is not a
/// post-quantum address and not this long is no address (it never falls through to another kind).
#[cfg(feature = "ycash")]
const TRANSPARENT_PAYLOAD_LEN: usize = 22;

impl serde::Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = <String as serde::Deserialize>::deserialize(deserializer)?;
        encoded.parse().map_err(serde::de::Error::custom)
    }
}

impl From<Address> for ZcashAddress {
    fn from(taddr: Address) -> Self {
        match taddr {
            Address::PayToScriptHash {
                network_kind,
                script_hash,
            } => ZcashAddress::from_transparent_p2sh(network_kind.into(), script_hash),
            Address::PayToPublicKeyHash {
                network_kind,
                pub_key_hash,
            } => ZcashAddress::from_transparent_p2pkh(network_kind.into(), pub_key_hash),
            Address::Tex {
                network_kind,
                validating_key_hash,
            } => ZcashAddress::from_tex(network_kind.into(), validating_key_hash),
            // ZcashAddress has no post-quantum form; its index key is the closest name.
            #[cfg(feature = "ycash")]
            Address::PayToPqKeyHash { network_kind, .. } => {
                ZcashAddress::from_transparent_p2pkh(network_kind.into(), taddr.hash_bytes())
            }
        }
    }
}

impl TryFrom<Address> for TransparentAddress {
    type Error = &'static str;

    fn try_from(taddr: Address) -> Result<Self, Self::Error> {
        match taddr {
            Address::PayToScriptHash { script_hash, .. } => Ok(Self::ScriptHash(script_hash)),
            Address::PayToPublicKeyHash { pub_key_hash, .. } => {
                Ok(Self::PublicKeyHash(pub_key_hash))
            }
            Address::Tex { .. } => Err("TransparentAddress can't be a Tex address"),
            #[cfg(feature = "ycash")]
            Address::PayToPqKeyHash { .. } => {
                Err("TransparentAddress can't be a post-quantum address")
            }
        }
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug_struct = f.debug_struct("TransparentAddress");

        match self {
            Address::PayToScriptHash {
                network_kind,
                script_hash,
            } => debug_struct
                .field("network_kind", network_kind)
                .field("script_hash", &hex::encode(script_hash))
                .finish(),
            Address::PayToPublicKeyHash {
                network_kind,
                pub_key_hash,
            } => debug_struct
                .field("network_kind", network_kind)
                .field("pub_key_hash", &hex::encode(pub_key_hash))
                .finish(),
            Address::Tex {
                network_kind,
                validating_key_hash,
            } => debug_struct
                .field("network_kind", network_kind)
                .field("validating_key_hash", &hex::encode(validating_key_hash))
                .finish(),
            #[cfg(feature = "ycash")]
            Address::PayToPqKeyHash {
                network_kind,
                scheme,
                key_hash,
            } => debug_struct
                .field("network_kind", network_kind)
                .field("scheme", scheme)
                .field("key_hash", &hex::encode(key_hash))
                .finish(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Ycash (D-9): ycash6 `EncodePQAddress`, "" for a scheme without a version.
        #[cfg(feature = "ycash")]
        if let Address::PayToPqKeyHash {
            network_kind,
            scheme,
            key_hash,
        } = self
        {
            let owner = kogany_vault::PqOwner {
                scheme: *scheme,
                hash: kogany_vault::Hash32(*key_hash),
            };
            return f.write_str(
                &kogany_yellowback::codecs::address::encode_pq(
                    &owner,
                    plain_pq_address_versions(*network_kind),
                )
                .unwrap_or_default(),
            );
        }
        let mut bytes = io::Cursor::new(Vec::new());
        let _ = self.zcash_serialize(&mut bytes);

        f.write_str(&bs58::encode(bytes.get_ref()).with_check().into_string())
    }
}

impl std::str::FromStr for Address {
    type Err = SerializationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try Base58Check (prefixes: t1, t3, tm, t2)
        if let Ok(data) = bs58::decode(s).with_check(None).into_vec() {
            // Ycash (kogany W7-b): a plain-YEC post-quantum address (D-Q-20).
            #[cfg(feature = "ycash")]
            {
                if let Some(address) = decode_plain_pq(&data) {
                    return Ok(address);
                }
                if data.len() != TRANSPARENT_PAYLOAD_LEN {
                    return Err(SerializationError::Parse("bad t-addr length"));
                }
            }
            return Address::zcash_deserialize(&data[..]);
        }

        // Try Bech32 (prefixes: tex, textest)
        let (hrp, payload) =
            bech32::decode(s).map_err(|_| SerializationError::Parse("invalid Bech32 encoding"))?;

        // We can’t meaningfully call `Address::zcash_deserialize` for Bech32 addresses, because
        // that method is explicitly reading two binary prefix bytes (the Base58Check version) + 20 hash bytes.
        // Bech32 textual addresses carry no such binary "version" on the wire, so there’s nothing in the
        // reader for zcash_deserialize to match.

        // Instead, we deserialize the Bech32 address here:

        if payload.len() != 20 {
            return Err(SerializationError::Parse("unexpected payload length"));
        }

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&payload);

        match hrp.as_str() {
            zcash_protocol::constants::mainnet::HRP_TEX_ADDRESS => Ok(Address::Tex {
                network_kind: NetworkKind::Mainnet,
                validating_key_hash: hash_bytes,
            }),

            zcash_protocol::constants::testnet::HRP_TEX_ADDRESS => Ok(Address::Tex {
                network_kind: NetworkKind::Testnet,
                validating_key_hash: hash_bytes,
            }),

            _ => Err(SerializationError::Parse("unknown Bech32 HRP")),
        }
    }
}

impl ZcashSerialize for Address {
    fn zcash_serialize<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        match self {
            Address::PayToScriptHash {
                network_kind,
                script_hash,
            } => {
                writer.write_all(&network_kind.b58_script_address_prefix())?;
                writer.write_all(script_hash)?
            }
            Address::PayToPublicKeyHash {
                network_kind,
                pub_key_hash,
            } => {
                writer.write_all(&network_kind.b58_pubkey_address_prefix())?;
                writer.write_all(pub_key_hash)?
            }
            Address::Tex {
                network_kind,
                validating_key_hash,
            } => {
                writer.write_all(&network_kind.tex_address_prefix())?;
                writer.write_all(validating_key_hash)?
            }
            #[cfg(feature = "ycash")]
            Address::PayToPqKeyHash {
                network_kind,
                scheme,
                key_hash,
            } => {
                // D-9: the version names the scheme; an unregistered scheme has none (ycash6
                // encodes "" for it) and writes the bare key hash, which decodes as nothing.
                if let Some((_, version)) = plain_pq_address_versions(*network_kind)
                    .iter()
                    .find(|(s, _)| s == scheme)
                {
                    writer.write_all(version)?;
                }
                writer.write_all(key_hash)?
            }
        }

        Ok(())
    }
}

impl ZcashDeserialize for Address {
    fn zcash_deserialize_from<R: io::Read>(
        reader: &mut ZcashReader<R>,
    ) -> Result<Self, SerializationError> {
        let mut version_bytes = [0; 2];
        reader.read_exact(&mut version_bytes)?;

        let mut hash_bytes = [0; 20];
        reader.read_exact(&mut hash_bytes)?;

        match version_bytes {
            zcash_protocol::constants::mainnet::B58_SCRIPT_ADDRESS_PREFIX => {
                Ok(Address::PayToScriptHash {
                    network_kind: NetworkKind::Mainnet,
                    script_hash: hash_bytes,
                })
            }
            zcash_protocol::constants::testnet::B58_SCRIPT_ADDRESS_PREFIX => {
                Ok(Address::PayToScriptHash {
                    network_kind: NetworkKind::Testnet,
                    script_hash: hash_bytes,
                })
            }
            zcash_protocol::constants::mainnet::B58_PUBKEY_ADDRESS_PREFIX => {
                Ok(Address::PayToPublicKeyHash {
                    network_kind: NetworkKind::Mainnet,
                    pub_key_hash: hash_bytes,
                })
            }
            zcash_protocol::constants::testnet::B58_PUBKEY_ADDRESS_PREFIX => {
                Ok(Address::PayToPublicKeyHash {
                    network_kind: NetworkKind::Testnet,
                    pub_key_hash: hash_bytes,
                })
            }
            _ => Err(SerializationError::Parse("bad t-addr version/type")),
        }
    }
}

impl Address {
    /// Create an address for the given public key hash and network.
    pub fn from_pub_key_hash(network_kind: NetworkKind, pub_key_hash: [u8; 20]) -> Self {
        Self::PayToPublicKeyHash {
            network_kind,
            pub_key_hash,
        }
    }

    /// Create an address for the given script hash and network.
    pub fn from_script_hash(network_kind: NetworkKind, script_hash: [u8; 20]) -> Self {
        Self::PayToScriptHash {
            network_kind,
            script_hash,
        }
    }

    /// Returns the network kind for this address.
    pub fn network_kind(&self) -> NetworkKind {
        match self {
            Address::PayToScriptHash { network_kind, .. } => *network_kind,
            Address::PayToPublicKeyHash { network_kind, .. } => *network_kind,
            Address::Tex { network_kind, .. } => *network_kind,
            #[cfg(feature = "ycash")]
            Address::PayToPqKeyHash { network_kind, .. } => *network_kind,
        }
    }

    /// Returns `true` if the address is `PayToScriptHash`, and `false` if it is `PayToPublicKeyHash`.
    pub fn is_script_hash(&self) -> bool {
        matches!(self, Address::PayToScriptHash { .. })
    }

    /// Returns the hash bytes for this address, regardless of the address type.
    ///
    /// # Correctness
    ///
    /// Use [`ZcashSerialize`] and [`ZcashDeserialize`] for consensus-critical serialization.
    pub fn hash_bytes(&self) -> [u8; 20] {
        match *self {
            Address::PayToScriptHash { script_hash, .. } => script_hash,
            Address::PayToPublicKeyHash { pub_key_hash, .. } => pub_key_hash,
            Address::Tex {
                validating_key_hash,
                ..
            } => validating_key_hash,
            // ycash6 `CScript::AddressHash` of a TX_PQPKH: Hash160(scheme ‖ keyHash).
            #[cfg(feature = "ycash")]
            Address::PayToPqKeyHash {
                scheme, key_hash, ..
            } => {
                let mut id = [0u8; 33];
                let (s, h) = id.split_at_mut(1);
                s.copy_from_slice(&[scheme]);
                h.copy_from_slice(&key_hash);
                kogany_vault::template::hash160(&id)
            }
        }
    }

    /// Turns the address into the `scriptPubKey` script that can be used in a coinbase output.
    ///
    /// TEX addresses are not supported and return an empty script.
    pub fn script(&self) -> Script {
        let mut script_bytes = Vec::new();

        match self {
            // https://developer.bitcoin.org/devguide/transactions.html#pay-to-script-hash-p2sh
            Address::PayToScriptHash { .. } => {
                script_bytes.push(OpCode::Hash160 as u8);
                script_bytes.push(OpCode::Push20Bytes as u8);
                script_bytes.extend(self.hash_bytes());
                script_bytes.push(OpCode::Equal as u8);
            }
            // https://developer.bitcoin.org/devguide/transactions.html#pay-to-public-key-hash-p2pkh
            Address::PayToPublicKeyHash { .. } => {
                script_bytes.push(OpCode::Dup as u8);
                script_bytes.push(OpCode::Hash160 as u8);
                script_bytes.push(OpCode::Push20Bytes as u8);
                script_bytes.extend(self.hash_bytes());
                script_bytes.push(OpCode::EqualVerify as u8);
                script_bytes.push(OpCode::CheckSig as u8);
            }
            Address::Tex { .. } => {}
            #[cfg(feature = "ycash")]
            Address::PayToPqKeyHash {
                scheme, key_hash, ..
            } => {
                let owner = kogany_vault::PqOwner {
                    scheme: *scheme,
                    hash: kogany_vault::Hash32(*key_hash),
                };
                script_bytes =
                    kogany_yellowback::codecs::script::pq_key_script(&owner).unwrap_or_default();
            }
        };

        Script::new(&script_bytes)
    }

    /// Create a TEX address from the given network kind and validating key hash.
    pub fn from_tex(network_kind: NetworkKind, validating_key_hash: [u8; 20]) -> Self {
        Self::Tex {
            network_kind,
            validating_key_hash,
        }
    }
}

#[cfg(test)]
// kogany: the Zcash-fixture tests are not built with `ycash`.
#[cfg_attr(feature = "ycash", allow(unused_imports, dead_code))]
mod tests {
    use ripemd::{Digest, Ripemd160};
    use secp256k1::PublicKey;
    use sha2::Sha256;

    use super::*;

    #[test]
    // kogany: Zcash transparent address fixtures (t1, t3, tm, t2 prefixes); not run on Ycash.
    #[cfg(not(feature = "ycash"))]
    fn serde_address_preserves_display_and_from_str() {
        for encoded in [
            "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd",
            "t1bmMa1wJDFdbc2TiURQP5BbBz6jHjUBuHq",
            "tmTc6trRhbv96kGfA99i7vrFwb5p7BVFwc3",
        ] {
            let address: Address = encoded.parse().unwrap();
            let json = serde_json::Value::String(encoded.into());
            assert_eq!(serde_json::to_value(address).unwrap(), json);
            assert_eq!(serde_json::from_value::<Address>(json).unwrap(), address);
        }

        for invalid in [
            serde_json::json!("invalid"),
            serde_json::json!(42),
            serde_json::json!(null),
        ] {
            assert!(serde_json::from_value::<Address>(invalid).is_err());
        }
    }

    trait ToAddressWithNetwork {
        /// Convert `self` to an `Address`, given the current `network`.
        fn to_address(&self, network: NetworkKind) -> Address;
    }

    impl ToAddressWithNetwork for Script {
        fn to_address(&self, network_kind: NetworkKind) -> Address {
            Address::PayToScriptHash {
                network_kind,
                script_hash: Address::hash_payload(self.as_raw_bytes()),
            }
        }
    }

    impl ToAddressWithNetwork for PublicKey {
        fn to_address(&self, network_kind: NetworkKind) -> Address {
            Address::PayToPublicKeyHash {
                network_kind,
                pub_key_hash: Address::hash_payload(&self.serialize()[..]),
            }
        }
    }

    impl Address {
        /// A hash of a transparent address payload, as used in
        /// transparent pay-to-script-hash and pay-to-publickey-hash
        /// addresses.
        ///
        /// The resulting hash in both of these cases is always exactly 20
        /// bytes.
        /// <https://en.bitcoin.it/Base58Check_encoding#Encoding_a_Bitcoin_address>
        fn hash_payload(bytes: &[u8]) -> [u8; 20] {
            let sha_hash = Sha256::digest(bytes);
            let ripe_hash = Ripemd160::digest(sha_hash);
            let mut payload = [0u8; 20];
            payload[..].copy_from_slice(&ripe_hash[..]);
            payload
        }
    }

    /// Ycash: a transparent address as YEW encodes it (`yew/core/src/params.rs`, the ycash6
    /// `chainparams.cpp` `PUBKEY_ADDRESS` / `SCRIPT_ADDRESS` rows) parses on every network.
    #[cfg(feature = "ycash")]
    #[test]
    fn ycash_transparent_prefixes_parse() {
        for (prefix, p2sh) in [
            ([0x1C, 0x28], false),
            ([0x1C, 0x2C], true),
            ([0x1C, 0x95], false),
            ([0x1C, 0x2A], true),
        ] {
            let mut data = prefix.to_vec();
            data.extend_from_slice(&[0x11u8; 20]);
            let text = bs58::encode(data).with_check().into_string();
            let address: Address = text.parse().unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(address.to_string(), text);
            assert_eq!(matches!(address, Address::PayToScriptHash { .. }), p2sh);
        }
    }

    /// Ycash (kogany W9-c finding 3): the plain post-quantum address round-trips, and its
    /// index hash is ycash6's `CScript::AddressHash` (Hash160(scheme || keyHash)).
    #[cfg(feature = "ycash")]
    #[test]
    fn plain_pq_address_round_trips() {
        let key_hash = [0x42u8; 32];
        let address = Address::PayToPqKeyHash {
            network_kind: NetworkKind::Regtest,
            scheme: 2,
            key_hash,
        };
        let text = address.to_string();
        assert!(text.starts_with("rqf"), "{text}");
        assert_eq!(text.len(), 53);
        assert_eq!(text.parse::<Address>().unwrap(), address);
        let mut id = vec![2u8];
        id.extend_from_slice(&key_hash);
        assert_eq!(address.hash_bytes(), Address::hash_payload(&id));
        let mut script = vec![0x20];
        script.extend_from_slice(&key_hash);
        script.extend_from_slice(&[0x52, 0xc2]);
        assert_eq!(address.script().as_raw_bytes(), script.as_slice());
        // the pre-D-9 form (2-byte version ‖ scheme ‖ keyHash) is not an address, and does not
        // fall through to a transparent one
        let mut data = vec![0x4C, 0x51, 2];
        data.extend_from_slice(&key_hash);
        let old_form = bs58::encode(data).with_check().into_string();
        assert!(old_form.parse::<Address>().is_err());
        // nor is a transparent version with a 32-byte body (ycashd checks the length)
        let mut data = NetworkKind::Mainnet.b58_pubkey_address_prefix().to_vec();
        data.extend_from_slice(&[0u8; 20]);
        let taddr = bs58::encode(&data).with_check().into_string();
        assert!(taddr.parse::<Address>().is_ok());
        data.extend_from_slice(&[0u8; 13]);
        let long_taddr = bs58::encode(data).with_check().into_string();
        assert!(long_taddr.parse::<Address>().is_err());
        // an address of an unregistered scheme does not exist: it renders as ""
        let unknown = Address::PayToPqKeyHash {
            network_kind: NetworkKind::Regtest,
            scheme: 9,
            key_hash,
        };
        assert_eq!(unknown.to_string(), "");
        // a TX_PQPKH output names it, as the address index reads it
        let output = crate::transparent::Output {
            value: crate::amount::Amount::try_from(1).unwrap(),
            lock_script: Script::new(&script),
        };
        assert_eq!(
            output.address(&crate::parameters::Network::new_regtest(Default::default())),
            Some(address)
        );
    }

    /// Ycash (D-9): the shared post-quantum address vectors (`testdata/yellowback/
    /// pq_address_vectors.json`, byte-identical to ycash6's, its SHA-256 checked against
    /// `testdata/yellowback/PIN`). Every plain-YEC vector parses to its network and key and
    /// prints back as itself; every YED vector and every invalid one is no transparent address
    /// (a failed post-quantum decode never falls through to another kind).
    #[cfg(feature = "ycash")]
    #[test]
    fn plain_pq_address_shared_vectors() {
        use sha2::Digest;
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/yellowback");
        let bytes = std::fs::read(dir.join("pq_address_vectors.json")).unwrap();
        let pin = std::fs::read_to_string(dir.join("PIN")).unwrap();
        let pinned = pin
            .lines()
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                let mut f = l.split_whitespace();
                let sha = f.next()?;
                (f.next()? == "testdata/yellowback/pq_address_vectors.json").then_some(sha)
            })
            .expect("pq_address_vectors.json is pinned");
        assert_eq!(hex::encode(sha2::Sha256::digest(&bytes)), pinned);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let kind = |n: &str| match n {
            "main" => NetworkKind::Mainnet,
            "test" => NetworkKind::Testnet,
            "regtest" => NetworkKind::Regtest,
            other => panic!("network {other}"),
        };
        let mut plain = 0;
        for row in v["valid"].as_array().unwrap() {
            let text = row["address"].as_str().unwrap();
            if row["coin"] != "yec" {
                assert!(text.parse::<Address>().is_err(), "YED {text}");
                continue;
            }
            plain += 1;
            let key_hash: [u8; 32] = hex::decode(row["keyhash"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let want = Address::PayToPqKeyHash {
                network_kind: kind(row["network"].as_str().unwrap()),
                scheme: u8::try_from(row["scheme"].as_u64().unwrap()).unwrap(),
                key_hash,
            };
            assert_eq!(text.parse::<Address>().unwrap(), want, "{text}");
            assert_eq!(want.to_string(), text);
            // serde (RPC parameters and answers) uses the same text
            assert_eq!(serde_json::to_value(want).unwrap(), text);
        }
        assert_eq!(plain, 36);
        for row in v["invalid"].as_array().unwrap() {
            let text = row["address"].as_str().unwrap();
            assert!(text.parse::<Address>().is_err(), "{} {text}", row["reason"]);
        }
    }

    #[test]
    // kogany: Zcash transparent address fixtures (t1, t3, tm, t2 prefixes); not run on Ycash.
    #[cfg(not(feature = "ycash"))]
    fn pubkey_mainnet() {
        let _init_guard = zakura_test::init();

        let pub_key = PublicKey::from_slice(&[
            3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41,
            111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78,
        ])
        .expect("A PublicKey from slice");

        let t_addr = pub_key.to_address(NetworkKind::Mainnet);

        assert_eq!(format!("{t_addr}"), "t1bmMa1wJDFdbc2TiURQP5BbBz6jHjUBuHq");
    }

    #[test]
    // kogany: Zcash transparent address fixtures (t1, t3, tm, t2 prefixes); not run on Ycash.
    #[cfg(not(feature = "ycash"))]
    fn pubkey_testnet() {
        let _init_guard = zakura_test::init();

        let pub_key = PublicKey::from_slice(&[
            3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41,
            111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78,
        ])
        .expect("A PublicKey from slice");

        let t_addr = pub_key.to_address(NetworkKind::Testnet);

        assert_eq!(format!("{t_addr}"), "tmTc6trRhbv96kGfA99i7vrFwb5p7BVFwc3");
    }

    #[test]
    // kogany: Zcash transparent address fixtures (t1, t3, tm, t2 prefixes); not run on Ycash.
    #[cfg(not(feature = "ycash"))]
    fn empty_script_mainnet() {
        let _init_guard = zakura_test::init();

        let script = Script::new(&[0u8; 20]);

        let t_addr = script.to_address(NetworkKind::Mainnet);

        assert_eq!(format!("{t_addr}"), "t3Y5pHwfgHbS6pDjj1HLuMFxhFFip1fcJ6g");
    }

    #[test]
    // kogany: Zcash transparent address fixtures (t1, t3, tm, t2 prefixes); not run on Ycash.
    #[cfg(not(feature = "ycash"))]
    fn empty_script_testnet() {
        let _init_guard = zakura_test::init();

        let script = Script::new(&[0; 20]);

        let t_addr = script.to_address(NetworkKind::Testnet);

        assert_eq!(format!("{t_addr}"), "t2L51LcmpA43UMvKTw2Lwtt9LMjwyqU2V1P");
    }

    #[test]
    // kogany: Zcash transparent address fixtures (t1, t3, tm, t2 prefixes); not run on Ycash.
    #[cfg(not(feature = "ycash"))]
    fn from_string() {
        let _init_guard = zakura_test::init();

        let t_addr: Address = "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd".parse().unwrap();

        assert_eq!(format!("{t_addr}"), "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd");
    }

    #[test]
    // kogany: Zcash transparent address fixtures (t1, t3, tm, t2 prefixes); not run on Ycash.
    #[cfg(not(feature = "ycash"))]
    fn debug() {
        let _init_guard = zakura_test::init();

        let t_addr: Address = "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd".parse().unwrap();

        assert_eq!(
            format!("{t_addr:?}"),
            "TransparentAddress { network_kind: Mainnet, script_hash: \"7d46a730d31f97b1930d3368a967c309bd4d136a\" }"
        );
    }
}

#[cfg(test)]
proptest! {

    #[test]
    fn transparent_address_roundtrip(taddr in any::<Address>()) {
        let _init_guard = zakura_test::init();

        let mut data = Vec::new();

        taddr.zcash_serialize(&mut data).expect("t-addr should serialize");

        let taddr2 = Address::zcash_deserialize(&data[..]).expect("randomized t-addr should deserialize");

        prop_assert_eq![taddr, taddr2];
    }
}
