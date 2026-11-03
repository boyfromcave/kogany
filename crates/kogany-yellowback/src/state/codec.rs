// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The C++ `SER_DISK` primitives the YED records are written with (`serialize.h`): fixed-width
//! little-endian integers, `u8` booleans and enumerations, `uint160` / `uint256` as raw bytes,
//! strings, byte vectors and scripts CompactSize-prefixed, vectors as CompactSize ‖ items, a
//! `COutPoint` as txid ‖ n LE32. The reader is total: every read past the end is `None`, and a
//! non-canonical CompactSize fails as `ReadCompactSize` throws.

use kogany_vault::{Hash32, OutPoint};

/// A record being written.
#[derive(Default)]
pub(crate) struct Writer(pub(crate) Vec<u8>);

impl Writer {
    pub(crate) fn new() -> Writer {
        Writer(Vec::new())
    }

    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    pub(crate) fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn i32(&mut self, v: i32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }

    pub(crate) fn hash(&mut self, h: &Hash32) -> &mut Self {
        self.raw(&h.0)
    }

    pub(crate) fn outpoint(&mut self, o: &OutPoint) -> &mut Self {
        self.raw(&o.to_bytes())
    }

    pub(crate) fn compact_size(&mut self, n: usize) -> &mut Self {
        let v = u64::try_from(n).unwrap_or(u64::MAX);
        if let Ok(b) = u8::try_from(v) {
            if b < 253 {
                return self.u8(b);
            }
        }
        if let Ok(w) = u16::try_from(v) {
            return self.u8(253).u16(w);
        }
        if let Ok(w) = u32::try_from(v) {
            return self.u8(254).u32(w);
        }
        self.u8(255).u64(v)
    }

    /// A byte vector, a string or a script: CompactSize ‖ bytes.
    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.compact_size(b.len()).raw(b)
    }

    /// A vector: CompactSize ‖ each item.
    pub(crate) fn vec<T>(&mut self, items: &[T], mut item: impl FnMut(&mut Self, &T)) -> &mut Self {
        self.compact_size(items.len());
        for i in items {
            item(self, i);
        }
        self
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

/// A record being read.
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    pub(crate) fn raw(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[b]| b)
    }

    /// The C++ bool: any non-zero byte is true.
    pub(crate) fn bool(&mut self) -> Option<bool> {
        self.u8().map(|b| b != 0)
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.take().map(u16::from_le_bytes)
    }

    pub(crate) fn i32(&mut self) -> Option<i32> {
        self.take().map(i32::from_le_bytes)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }

    pub(crate) fn i64(&mut self) -> Option<i64> {
        self.take().map(i64::from_le_bytes)
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_le_bytes)
    }

    pub(crate) fn hash(&mut self) -> Option<Hash32> {
        self.take::<32>().map(Hash32)
    }

    pub(crate) fn outpoint(&mut self) -> Option<OutPoint> {
        OutPoint::from_slice(&self.take::<36>()?)
    }

    pub(crate) fn compact_size(&mut self) -> Option<usize> {
        let v = match self.u8()? {
            253 => {
                let v = u64::from(self.u16()?);
                (v >= 253).then_some(v)?
            }
            254 => {
                let v = u64::from(self.u32()?);
                (v >= 0x1_0000).then_some(v)?
            }
            255 => {
                let v = self.u64()?;
                (v >= 0x1_0000_0000).then_some(v)?
            }
            b => u64::from(b),
        };
        usize::try_from(v).ok()
    }

    pub(crate) fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.compact_size()?;
        self.raw(n).map(<[u8]>::to_vec)
    }

    pub(crate) fn string(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?).ok()
    }

    pub(crate) fn vec<T>(
        &mut self,
        mut item: impl FnMut(&mut Self) -> Option<T>,
    ) -> Option<Vec<T>> {
        let n = self.compact_size()?;
        // Each item is at least one byte: bound the allocation by what is left.
        let mut out = Vec::with_capacity(n.min(self.0.len()));
        for _ in 0..n {
            out.push(item(self)?);
        }
        Some(out)
    }

    pub(crate) fn done(&self) -> bool {
        self.0.is_empty()
    }
}
