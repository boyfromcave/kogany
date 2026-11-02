//! The JSON encodings ycashd's vault RPCs use (`ycash6/src/rpc/vault.cpp`, `rpc/server.cpp`).

use kogany_vault::{Hash32, OutPoint, PqOwner, Tag};
use serde::{Serialize, Serializer};
use serde_json::value::RawValue;
use zakura_rpc::server::{
    error::LegacyCode,
    jsonrpc::{ErrorObject, RpcResult},
};

/// Zatoshi per YEC.
const COIN: i64 = 100_000_000;

/// An amount in zatoshi, written as YEC with exactly eight decimals, as ycashd's
/// `ValueFromAmount` writes it (`rpc/server.cpp`: `"%s%d.%08d"`), so `0.5` YEC is `0.50000000`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Yec(pub i64);

impl Yec {
    /// The decimal text of the amount.
    pub fn text(self) -> String {
        let sign = if self.0 < 0 { "-" } else { "" };
        let abs = self.0.unsigned_abs();
        // COIN is positive, so the cast is exact.
        let coin = COIN as u64;
        format!("{sign}{}.{:08}", abs / coin, abs % coin)
    }
}

impl Serialize for Yec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw = RawValue::from_string(self.text()).map_err(serde::ser::Error::custom)?;
        raw.serialize(serializer)
    }
}

/// A 32-byte id in display order: the C++ `uint256::GetHex()` (txids, set ids, block hashes,
/// the state hash), which reverses the internal bytes.
pub fn display_hex(h: &Hash32) -> String {
    let mut b = h.0;
    b.reverse();
    hex::encode(b)
}

/// Bytes in their own order: the C++ `HexStr(begin, end)` (tags, keys, scripts, the intent's
/// recipient and vault hashes, sighashes).
pub fn raw_hex(b: &[u8]) -> String {
    hex::encode(b)
}

/// `"txid:n"`, the C++ `OutPointStr`.
pub fn outpoint_text(o: &OutPoint) -> String {
    format!("{}:{}", display_hex(&o.txid), o.n)
}

/// A pqkeyid, `scheme || keyhash` in internal order (the C++ `PQKeyIdHex`).
pub fn pqkeyid_hex(owner: &PqOwner) -> String {
    let mut b = Vec::with_capacity(33);
    b.push(owner.scheme);
    b.extend_from_slice(&owner.hash.0);
    hex::encode(b)
}

/// A tag's printable text up to its first zero byte, `?` for anything not printable ASCII (the
/// C++ `TagText`).
pub fn tag_text(t: &Tag) -> String {
    t.0.iter()
        .take_while(|c| **c != 0)
        .map(|c| {
            if (0x20..0x7f).contains(c) {
                char::from(*c)
            } else {
                '?'
            }
        })
        .collect()
}

/// An RPC error with one of ycashd's legacy codes.
pub fn rpc_error(code: LegacyCode, message: impl Into<String>) -> ErrorObject {
    ErrorObject::new(code, message)
}

/// Hex text as bytes: ycashd's `ParseHexV`, which refuses odd lengths, non-hex digits and the
/// empty string with `-8 "<name> must be hexadecimal string (not '<text>')"`.
pub fn parse_hex(text: &str, name: &str) -> RpcResult<Vec<u8>> {
    match hex::decode(text) {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        _ => Err(rpc_error(
            LegacyCode::InvalidParameter,
            format!("{name} must be hexadecimal string (not '{text}')"),
        )),
    }
}

/// A 64-digit display-order id as its internal bytes (ycashd's `ParseHashV`, which also needs
/// the 32 bytes).
pub fn parse_display_hash(text: &str, name: &str) -> RpcResult<Hash32> {
    let bytes = parse_hex(text, name)?;
    let mut hash = Hash32::from_slice(&bytes).ok_or_else(|| {
        rpc_error(
            LegacyCode::InvalidParameter,
            format!("{name} must be of length 64 (not {})", text.len()),
        )
    })?;
    hash.0.reverse();
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_have_eight_decimals() {
        assert_eq!(Yec(50_000_000).text(), "0.50000000");
        assert_eq!(Yec(0).text(), "0.00000000");
        assert_eq!(Yec(-1).text(), "-0.00000001");
        assert_eq!(Yec(2_100_000_000_000_000).text(), "21000000.00000000");
        assert_eq!(Yec(i64::MIN).text(), "-92233720368.54775808");
        #[derive(Serialize)]
        struct Wrapped {
            v: Yec,
        }
        assert_eq!(
            serde_json::to_string(&Wrapped { v: Yec(123) }).ok(),
            Some("{\"v\":0.00000123}".to_owned())
        );
    }

    #[test]
    fn hashes_display_reversed() {
        let mut h = Hash32::ZERO;
        h.0[0] = 0xab;
        let text = display_hex(&h);
        assert!(text.ends_with("ab"));
        assert_eq!(parse_display_hash(&text, "setid").ok(), Some(h));
        assert!(parse_display_hash("zz", "setid").is_err());
        assert!(parse_display_hash("00", "setid").is_err());
    }

    #[test]
    fn tag_text_stops_at_zero() {
        assert_eq!(tag_text(&Tag(*b"YED\0")), "YED");
        assert_eq!(tag_text(&Tag([0x57, 0x01, 0x45, 0x43])), "W?EC");
    }
}
