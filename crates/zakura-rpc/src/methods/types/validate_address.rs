//! Response type for the `validateaddress` RPC.

use crate::server::jsonrpc::RpcResult;
use derive_new::new;
use getset::{CopyGetters, Getters};
use zakura_chain::{
    parameters::{Network, NetworkKind},
    primitives,
};

use crate::methods::types::validate_address;

/// `validateaddress` response
#[derive(
    Clone,
    Default,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    Getters,
    CopyGetters,
    new,
)]
pub struct ValidateAddressResponse {
    /// Whether the address is valid.
    ///
    /// If not, this is the only property returned.
    #[serde(rename = "isvalid")]
    #[getset(get_copy = "pub")]
    pub(crate) is_valid: bool,

    /// The zcash address that has been validated.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[getset(get = "pub")]
    pub(crate) address: Option<String>,

    /// Ycash (W1-Y6): the hex `scriptPubKey` of a valid address, as ycashd sends it
    /// (`ycash6 src/rpc/misc.cpp`, `validateaddress`); yolo builds its payout output from it.
    #[cfg(feature = "ycash")]
    #[serde(
        rename = "scriptPubKey",
        skip_serializing_if = "Option::is_none",
        default
    )]
    #[new(default)]
    pub(crate) script_pub_key: Option<String>,

    /// If the key is a script.
    #[serde(rename = "isscript")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[getset(get_copy = "pub")]
    pub(crate) is_script: Option<bool>,

    /// Ycash (W7-c): the scheme of a post-quantum address (`sqs…`/`tqs…`/`rqs…` = 1,
    /// `sqf…`/`tqf…`/`rqf…` = 2, D-9), 1 =
    /// SLH-DSA-SHA2-128s, 2 = FN-DSA-512 (`ycash6 src/rpc/misc.cpp`, `DescribeAddressVisitor`).
    #[cfg(feature = "ycash")]
    #[serde(rename = "pqscheme", skip_serializing_if = "Option::is_none", default)]
    #[new(default)]
    pub(crate) pq_scheme: Option<u8>,

    /// Ycash (W7-c): the key hash of a post-quantum address, as pushed in its TX_PQPKH script.
    #[cfg(feature = "ycash")]
    #[serde(rename = "pqkeyhash", skip_serializing_if = "Option::is_none", default)]
    #[new(default)]
    pub(crate) pq_key_hash: Option<String>,
}

impl ValidateAddressResponse {
    /// Creates an empty response with `isvalid` of false.
    pub fn invalid() -> Self {
        Self::default()
    }
}

/// Checks if a zcash transparent address of type P2PKH, P2SH or TEX is valid.
/// Returns information about the given address if valid.
pub fn validate_address(
    network: Network,
    raw_address: String,
) -> RpcResult<ValidateAddressResponse> {
    let Ok(address) = raw_address.parse::<zcash_address::ZcashAddress>() else {
        // Ycash (W7-c): a plain-YEC post-quantum address, which ycashd decodes after the
        // transparent forms.
        #[cfg(feature = "ycash")]
        if let Some(pq) = super::ycash::decode_pq_address(&network, &raw_address) {
            return Ok(ValidateAddressResponse {
                is_valid: true,
                address: Some(pq.address),
                script_pub_key: Some(pq.script_pub_key),
                is_script: Some(false),
                pq_scheme: Some(pq.scheme),
                pq_key_hash: Some(pq.key_hash),
            });
        }
        return Ok(ValidateAddressResponse::invalid());
    };

    let address = match address.convert::<primitives::Address>() {
        Ok(address) => address,
        Err(err) => {
            tracing::debug!(?err, "conversion error");
            return Ok(ValidateAddressResponse::invalid());
        }
    };

    // We want to match zcashd's behaviour
    if !address.is_transparent() {
        return Ok(ValidateAddressResponse::invalid());
    }

    // Testnet & regtest share format; only mainnet differs.
    let addr_is_mainnet = matches!(address.network(), NetworkKind::Mainnet);
    let net_is_mainnet = network.kind() == NetworkKind::Mainnet;

    if addr_is_mainnet != net_is_mainnet {
        tracing::info!(
            ?network,
            address_network = ?address.network(),
            "invalid address in validateaddress RPC: Zakura's configured network must match address network"
        );
        return Ok(validate_address::ValidateAddressResponse::invalid());
    }

    Ok(validate_address::ValidateAddressResponse {
        address: Some(raw_address),
        #[cfg(feature = "ycash")]
        script_pub_key: match &address {
            primitives::Address::Transparent(taddr) => {
                Some(hex::encode(taddr.script().as_raw_bytes()))
            }
            _ => None,
        },
        is_valid: true,
        is_script: Some(address.is_script_hash()),
        #[cfg(feature = "ycash")]
        pq_scheme: None,
        #[cfg(feature = "ycash")]
        pq_key_hash: None,
    })
}
