//! The minimal script layer the templates and acts need: opcode bytes, a tokenizer with the
//! C++ `CScript::GetOp` semantics, and a builder with the C++ `CScript <<` encodings.
//!
//! This is not an interpreter; script evaluation lives in the script crate (W3). The template
//! parsers only split scripts into tokens and compare rebuilt bytes.

/// Opcode bytes used by the templates and acts.
pub mod op {
    /// `OP_0` (an empty push).
    pub const OP_0: u8 = 0x00;
    /// `OP_PUSHDATA1`.
    pub const OP_PUSHDATA1: u8 = 0x4c;
    /// `OP_PUSHDATA2`.
    pub const OP_PUSHDATA2: u8 = 0x4d;
    /// `OP_PUSHDATA4`.
    pub const OP_PUSHDATA4: u8 = 0x4e;
    /// `OP_1NEGATE`.
    pub const OP_1NEGATE: u8 = 0x4f;
    /// `OP_RESERVED`.
    pub const OP_RESERVED: u8 = 0x50;
    /// `OP_1`.
    pub const OP_1: u8 = 0x51;
    /// `OP_2`.
    pub const OP_2: u8 = 0x52;
    /// `OP_3`.
    pub const OP_3: u8 = 0x53;
    /// `OP_4`.
    pub const OP_4: u8 = 0x54;
    /// `OP_16`.
    pub const OP_16: u8 = 0x60;
    /// `OP_IF`.
    pub const OP_IF: u8 = 0x63;
    /// `OP_ELSE`.
    pub const OP_ELSE: u8 = 0x67;
    /// `OP_ENDIF`.
    pub const OP_ENDIF: u8 = 0x68;
    /// `OP_VERIFY`.
    pub const OP_VERIFY: u8 = 0x69;
    /// `OP_RETURN`.
    pub const OP_RETURN: u8 = 0x6a;
    /// `OP_2DROP`.
    pub const OP_2DROP: u8 = 0x6d;
    /// `OP_DROP`.
    pub const OP_DROP: u8 = 0x75;
    /// `OP_DUP`.
    pub const OP_DUP: u8 = 0x76;
    /// `OP_EQUAL`.
    pub const OP_EQUAL: u8 = 0x87;
    /// `OP_EQUALVERIFY`.
    pub const OP_EQUALVERIFY: u8 = 0x88;
    /// `OP_HASH160`.
    pub const OP_HASH160: u8 = 0xa9;
    /// `OP_CHECKSIG`.
    pub const OP_CHECKSIG: u8 = 0xac;
    /// `OP_CHECKLOCKTIMEVERIFY` (`OP_NOP2`, BIP65).
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
    /// `OP_CHECKSEQUENCEVERIFY` (`OP_NOP3`, BIP112), active under the Vault branch.
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
    /// `OP_CHECKSETSIG` (upgrade plan §15.2, U-10): above `OP_NOP10`, never 0xbb..0xbf.
    pub const OP_CHECKSETSIG: u8 = 0xc0;
    /// `OP_CHECKSETDORMANT` (upgrade plan §15.2).
    pub const OP_CHECKSETDORMANT: u8 = 0xc1;
    /// `OP_CHECKPQSIG` (quantum plan §4.2): the owner slot's opcode.
    pub const OP_CHECKPQSIG: u8 = 0xc2;
}

use op::*;

/// One script token: the opcode byte and, for a data push (`opcode <= OP_PUSHDATA4`), the
/// pushed bytes. Other opcodes carry no data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token<'a> {
    /// The opcode byte.
    pub op: u8,
    /// The pushed bytes (empty for a non-push opcode, and for `OP_0`).
    pub data: &'a [u8],
}

impl Token<'_> {
    /// A push-type token in the template sense (C++ `IsPushTok`): `opcode <= OP_16`, except
    /// `OP_RESERVED`.
    pub fn is_push(&self) -> bool {
        self.op <= OP_16 && self.op != OP_RESERVED
    }

    /// A data push (`opcode <= OP_PUSHDATA4`).
    pub fn is_data_push(&self) -> bool {
        self.op <= OP_PUSHDATA4
    }

    /// `OP_1..OP_16` as its number.
    pub fn small_int(&self) -> Option<u8> {
        (OP_1..=OP_16)
            .contains(&self.op)
            .then(|| self.op.wrapping_sub(OP_1 - 1))
    }
}

/// Reads one token at `pos` (C++ `GetScriptOp`). Returns the token and the next position, or
/// `None` at the end of the script or on a truncated push.
pub fn get_op(script: &[u8], pos: usize) -> Option<(Token<'_>, usize)> {
    let rest = script.get(pos..)?;
    let (&opcode, rest) = rest.split_first()?;
    let (size, rest) = match opcode {
        o if o < OP_PUSHDATA1 => (usize::from(o), rest),
        OP_PUSHDATA1 => {
            let (&n, rest) = rest.split_first()?;
            (usize::from(n), rest)
        }
        OP_PUSHDATA2 => {
            let (n, rest) = rest.split_at_checked(2)?;
            (usize::from(u16::from_le_bytes(n.try_into().ok()?)), rest)
        }
        OP_PUSHDATA4 => {
            let (n, rest) = rest.split_at_checked(4)?;
            (
                usize::try_from(u32::from_le_bytes(n.try_into().ok()?)).ok()?,
                rest,
            )
        }
        _ => (0, rest),
    };
    let (data, rest) = rest.split_at_checked(size)?;
    let next = script.len().checked_sub(rest.len())?;
    Some((Token { op: opcode, data }, next))
}

/// Splits a whole script into tokens; `None` on a truncated push (C++ `Tokenize`).
pub fn tokenize(script: &[u8]) -> Option<Vec<Token<'_>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < script.len() {
        let (t, next) = get_op(script, pos)?;
        out.push(t);
        pos = next;
    }
    Some(out)
}

/// Every token parses and is `<= OP_16` (C++ `CScript::IsPushOnly`, which counts
/// `OP_RESERVED` as push-type).
pub fn is_push_only(script: &[u8]) -> bool {
    tokenize(script).is_some_and(|t| t.iter().all(|t| t.op <= OP_16))
}

/// The minimal `CScriptNum` serialisation of `n` (empty for zero).
pub fn script_num(n: i64) -> Vec<u8> {
    let mut out = Vec::new();
    let neg = n < 0;
    let mut abs = n.unsigned_abs();
    while abs != 0 {
        let [low, ..] = abs.to_le_bytes();
        out.push(low);
        abs = abs.checked_shr(8).unwrap_or(0);
    }
    if let Some(last) = out.last_mut() {
        if *last & 0x80 != 0 {
            out.push(if neg { 0x80 } else { 0x00 });
        } else if neg {
            *last |= 0x80;
        }
    }
    out
}

/// A script under construction, with the C++ `CScript <<` encodings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Builder(Vec<u8>);

impl Builder {
    /// An empty script.
    pub fn new() -> Builder {
        Builder(Vec::new())
    }

    /// Appends an opcode byte (`CScript << opcodetype`).
    pub fn op(mut self, opcode: u8) -> Builder {
        self.0.push(opcode);
        self
    }

    /// Appends a minimal data push of `data` (`CScript << std::vector<unsigned char>`: a
    /// direct length below 0x4c, else PUSHDATA1/2/4). Never an `OP_n` for one byte.
    pub fn push(mut self, data: &[u8]) -> Builder {
        let len = data.len();
        if let Ok(n) = u8::try_from(len) {
            if n < OP_PUSHDATA1 {
                self.0.push(n);
            } else {
                self.0.push(OP_PUSHDATA1);
                self.0.push(n);
            }
        } else if let Ok(n) = u16::try_from(len) {
            self.0.push(OP_PUSHDATA2);
            self.0.extend_from_slice(&n.to_le_bytes());
        } else {
            // A push over 4 GiB cannot occur: no script is that long.
            let n = u32::try_from(len).unwrap_or(u32::MAX);
            self.0.push(OP_PUSHDATA4);
            self.0.extend_from_slice(&n.to_le_bytes());
        }
        self.0.extend_from_slice(data);
        self
    }

    /// Appends a number (`CScript << int64_t`): `OP_0`, `OP_1NEGATE`, `OP_1..OP_16`, else a
    /// minimal `CScriptNum` push.
    pub fn num(mut self, n: i64) -> Builder {
        match n {
            0 => self.0.push(OP_0),
            -1 => self.0.push(OP_1NEGATE),
            1..=16 => {
                let small = u8::try_from(n).unwrap_or(0);
                self.0.push(small.wrapping_add(OP_1 - 1));
            }
            _ => return self.push(&script_num(n)),
        }
        self
    }

    /// The script bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
