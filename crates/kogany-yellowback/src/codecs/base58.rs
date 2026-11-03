// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Base58 and Base58Check (ycash6 `src/base58.cpp`), with the C++ decoder's exact acceptance:
//! the input is read as a C string (it ends at the first NUL byte), leading and trailing C-locale
//! white space is skipped, and anything else outside the alphabet fails. An address decoder that
//! is stricter or looser than the C++ one would disagree with ycashd on which strings are
//! addresses (`yed_validateaddress`, the `yed_*` RPCs that take one).

use sha2::{Digest, Sha256};

/// The alphabet: every alphanumeric character except `0`, `I`, `O` and `l`.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// C `isspace` in the "C" locale: space, `\t`, `\n`, `\v`, `\f`, `\r`.
fn is_space(c: u8) -> bool {
    c == b' ' || (0x09..=0x0d).contains(&c)
}

/// The double SHA-256 (`Hash`) of `data`.
fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// The 4-byte Base58Check checksum: the first four bytes of `sha256d(data)`.
fn checksum(data: &[u8]) -> [u8; 4] {
    let [a, b, c, d, ..] = sha256d(data);
    [a, b, c, d]
}

/// `EncodeBase58`: leading zero bytes become `1`s, the rest is the big-endian base-58 number.
pub fn encode_base58(data: &[u8]) -> String {
    let zeroes = data.iter().take_while(|&&b| b == 0).count();
    // Big-endian base-58 digits, built by "digits = digits * 256 + byte".
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data.iter().skip(zeroes) {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut().rev() {
            // carry < 256 + 256 * 57 < 2^15: no overflow.
            carry = carry.saturating_add(u32::from(*d).saturating_mul(256));
            *d = u8::try_from(carry % 58).unwrap_or(0);
            carry /= 58;
        }
        while carry > 0 {
            digits.insert(0, u8::try_from(carry % 58).unwrap_or(0));
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeroes.saturating_add(digits.len()));
    out.extend(std::iter::repeat_n('1', zeroes));
    for d in digits {
        if let Some(&c) = ALPHABET.get(usize::from(d)) {
            out.push(char::from(c));
        }
    }
    out
}

/// `DecodeBase58`: `None` for a character outside the alphabet or white space inside the string.
pub fn decode_base58(s: &str) -> Option<Vec<u8>> {
    // c_str(): the C++ decoder stops at the first NUL.
    let bytes = s.as_bytes();
    let bytes = bytes
        .iter()
        .position(|&b| b == 0)
        .and_then(|n| bytes.get(..n))
        .unwrap_or(bytes);
    let mut it = bytes.iter().copied().peekable();
    while it.next_if(|&c| is_space(c)).is_some() {}
    let mut zeroes = 0usize;
    while it.next_if_eq(&b'1').is_some() {
        zeroes = zeroes.saturating_add(1);
    }
    // Big-endian base-256 bytes, built by "b256 = b256 * 58 + digit".
    let mut b256: Vec<u8> = Vec::new();
    while let Some(c) = it.next_if(|&c| !is_space(c)) {
        let digit = ALPHABET.iter().position(|&a| a == c)?;
        let mut carry = u32::try_from(digit).ok()?;
        for b in b256.iter_mut().rev() {
            // carry < 58 + 58 * 255 < 2^14: no overflow.
            carry = carry.saturating_add(u32::from(*b).saturating_mul(58));
            *b = u8::try_from(carry & 0xff).ok()?;
            carry >>= 8;
        }
        while carry > 0 {
            b256.insert(0, u8::try_from(carry & 0xff).ok()?);
            carry >>= 8;
        }
    }
    while it.next_if(|&c| is_space(c)).is_some() {}
    if it.next().is_some() {
        return None;
    }
    let mut out = vec![0u8; zeroes];
    out.extend(b256.into_iter().skip_while(|&b| b == 0));
    Some(out)
}

/// `EncodeBase58Check`: `data` followed by its 4-byte checksum, in Base58.
pub fn encode_base58_check(data: &[u8]) -> String {
    let mut v = data.to_vec();
    v.extend_from_slice(&checksum(data));
    encode_base58(&v)
}

/// `DecodeBase58Check`: the payload without its checksum; `None` if the string does not decode,
/// is shorter than the checksum, or the checksum does not match.
pub fn decode_base58_check(s: &str) -> Option<Vec<u8>> {
    let mut v = decode_base58(s)?;
    let body_len = v.len().checked_sub(4)?;
    let (body, sum) = v.split_at(body_len);
    if checksum(body) != sum {
        return None;
    }
    v.truncate(body_len);
    Some(v)
}
