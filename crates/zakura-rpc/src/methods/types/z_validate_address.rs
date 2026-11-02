//! Response type for the `z_validateaddress` RPC.

use crate::server::jsonrpc::RpcResult;
use derive_new::new;
use getset::{CopyGetters, Getters};

use zakura_chain::{
    parameters::{Network, NetworkKind},
    primitives::Address,
};

/// `z_validateaddress` response
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
pub struct ZValidateAddressResponse {
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

    /// The type of the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[getset(get_copy = "pub")]
    pub(crate) address_type: Option<ZValidateAddressType>,

    /// Whether the address is yours or not.
    ///
    /// Always false for now since Zebra doesn't have a wallet yet.
    #[serde(rename = "ismine")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[getset(get_copy = "pub")]
    pub(crate) is_mine: Option<bool>,

    /// Ycash (S5 parity): ycashd's deprecated `type`, the address type again (on by default,
    /// `-allowdeprecated=addrtype`; ycash6 `src/rpc/misc.cpp` `pushAddressType`).
    #[cfg(feature = "ycash")]
    #[serde(rename = "type", skip_serializing_if = "Option::is_none", default)]
    #[new(default)]
    pub(crate) deprecated_type: Option<ZValidateAddressType>,

    /// Ycash (S5 parity): a Sapling address's diversifier, hex (`HexStr(zaddr.d)`).
    #[cfg(feature = "ycash")]
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[new(default)]
    pub(crate) diversifier: Option<String>,

    /// Ycash (S5 parity): a Sapling address's `pk_d`, as `uint256::GetHex` prints it.
    #[cfg(feature = "ycash")]
    #[serde(
        rename = "diversifiedtransmissionkey",
        skip_serializing_if = "Option::is_none",
        default
    )]
    #[new(default)]
    pub(crate) diversified_transmission_key: Option<String>,
}

impl ZValidateAddressResponse {
    /// Creates an empty response with `isvalid` of false.
    pub fn invalid() -> Self {
        Self::default()
    }
}

/// Address types supported by the `z_validateaddress` RPC according to
/// <https://zcash.github.io/rpc/z_validateaddress.html>.
#[derive(Copy, Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ZValidateAddressType {
    /// The `p2pkh` address type.
    P2pkh,
    /// The `p2sh` address type.
    P2sh,
    /// The `sapling` address type.
    Sapling,
    /// The `unified` address type.
    Unified,
}

impl From<&Address> for ZValidateAddressType {
    fn from(address: &Address) -> Self {
        match address {
            Address::Transparent(_) => {
                if address.is_script_hash() {
                    Self::P2sh
                } else {
                    Self::P2pkh
                }
            }
            Address::Sapling { .. } => Self::Sapling,
            Address::Unified { .. } => Self::Unified,
        }
    }
}

/// Checks if a zcash address of type P2PKH, P2SH, TEX, SAPLING or UNIFIED is valid.
/// Returns information about the given address if valid.
pub fn z_validate_address(
    network: Network,
    raw_address: String,
) -> RpcResult<ZValidateAddressResponse> {
    let Ok(address) = raw_address.parse::<zcash_address::ZcashAddress>() else {
        return Ok(ZValidateAddressResponse::invalid());
    };

    let address = match address.convert::<Address>() {
        Ok(address) => address,
        Err(err) => {
            tracing::debug!(?err, "conversion error");
            return Ok(ZValidateAddressResponse::invalid());
        }
    };

    let is_transparent = matches!(address, Address::Transparent(_));

    // Collapse regtest to testnet. Only applied if address is transparent (P2PKH or P2SH).
    let expected_kind = match (is_transparent, network.kind()) {
        (true, NetworkKind::Regtest) => NetworkKind::Testnet,
        _ => network.kind(),
    };

    if address.network() == expected_kind {
        // Ycash (S5 parity): a node has no wallet, so it answers as ycashd -disablewallet does
        // (`DescribePaymentAddressVisitor` without `pwalletMain`): no `ismine`, the deprecated
        // `type`, and a Sapling address's diversifier and transmission key.
        #[cfg(feature = "ycash")]
        {
            let address_type = ZValidateAddressType::from(&address);
            let sapling = match &address {
                Address::Sapling { address, .. } => {
                    let bytes = address.to_bytes();
                    let mut pk_d = bytes[11..].to_vec();
                    pk_d.reverse();
                    Some((hex::encode(&bytes[..11]), hex::encode(pk_d)))
                }
                _ => None,
            };
            Ok(ZValidateAddressResponse {
                is_valid: true,
                address: Some(raw_address),
                address_type: Some(address_type),
                is_mine: None,
                deprecated_type: Some(address_type),
                diversifier: sapling.as_ref().map(|(d, _)| d.clone()),
                diversified_transmission_key: sapling.map(|(_, pk_d)| pk_d),
            })
        }
        #[cfg(not(feature = "ycash"))]
        Ok(ZValidateAddressResponse {
            is_valid: true,
            address: Some(raw_address),
            address_type: Some(ZValidateAddressType::from(&address)),
            is_mine: Some(false),
        })
    } else {
        tracing::info!(
            ?network,
            address_network = ?address.network(),
            "invalid address network in z_validateaddress RPC: address is for {:?} but Zakura is on {:?}",
            address.network(),
            network
        );

        Ok(ZValidateAddressResponse::invalid())
    }
}

/// S5 parity (`z_validateaddress_nowallet.py`): kogany answers as ycashd `-disablewallet`.
#[cfg(all(test, feature = "ycash"))]
mod ycash_tests {
    use zakura_chain::parameters::Network;

    use super::*;

    #[test]
    fn ycash_answers_as_a_node_without_a_wallet() {
        let regtest = Network::new_regtest(Default::default());
        let json = |a: &str| {
            serde_json::to_value(z_validate_address(regtest.clone(), a.to_owned()).expect("ok"))
                .expect("json")
        };
        let t = json("smKfGwyRJhcNVEQL3ZC2Kitx3WhmHHGLxFR");
        assert_eq!(
            t,
            serde_json::json!({
                "isvalid": true,
                "address": "smKfGwyRJhcNVEQL3ZC2Kitx3WhmHHGLxFR",
                "address_type": "p2pkh",
                "type": "p2pkh",
            })
        );
        let z = json("yregtestsapling1xl84ekz6stprmvrp39s77mf9t953nqjndwlcjtzfrr3cgjjez87639xm4u9pfuvylrhec7x0pw7");
        assert_eq!(z["address_type"], "sapling");
        assert_eq!(z["type"], "sapling");
        assert!(z.get("ismine").is_none());
        assert_eq!(z["diversifier"].as_str().map(str::len), Some(22));
        assert_eq!(
            z["diversifiedtransmissionkey"].as_str().map(str::len),
            Some(64)
        );
        assert_eq!(json("not-an-address"), serde_json::json!({ "isvalid": false }));
    }
}
