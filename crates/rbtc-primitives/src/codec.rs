use std::io::{self, Read, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CodecError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid varint encoding")]
    InvalidVarInt,
    #[error("data too large: {0} bytes")]
    TooLarge(u64),
    #[error("unexpected end of data")]
    UnexpectedEof,
    #[error("invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, CodecError>;

/// Bitcoin variable-length integer (CompactSize / VarInt)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt(pub u64);

impl VarInt {
    pub fn len(&self) -> usize {
        match self.0 {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x10000..=0xffffffff => 5,
            _ => 9,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

pub trait Encodable {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize>;

    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf).expect("vec write never fails");
        buf
    }
}

pub trait Decodable: Sized {
    fn decode<R: Read>(r: &mut R) -> Result<Self>;

    fn decode_from_slice(bytes: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(bytes);
        Self::decode(&mut cursor)
    }
}

// ── Primitive impls ──────────────────────────────────────────────────────────

impl Encodable for u8 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_all(&[*self])?;
        Ok(1)
    }
}

impl Decodable for u8 {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl Encodable for u16 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_all(&self.to_le_bytes())?;
        Ok(2)
    }
}

impl Decodable for u16 {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }
}

impl Encodable for u32 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_all(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl Decodable for u32 {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
}

impl Encodable for i32 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_all(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl Decodable for i32 {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }
}

impl Encodable for u64 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_all(&self.to_le_bytes())?;
        Ok(8)
    }
}

impl Decodable for u64 {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl Encodable for i64 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_all(&self.to_le_bytes())?;
        Ok(8)
    }
}

impl Decodable for i64 {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }
}

// ── VarInt ───────────────────────────────────────────────────────────────────

impl Encodable for VarInt {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        match self.0 {
            n @ 0..=0xfc => {
                w.write_all(&[n as u8])?;
                Ok(1)
            }
            n @ 0xfd..=0xffff => {
                w.write_all(&[0xfd])?;
                w.write_all(&(n as u16).to_le_bytes())?;
                Ok(3)
            }
            n @ 0x10000..=0xffffffff => {
                w.write_all(&[0xfe])?;
                w.write_all(&(n as u32).to_le_bytes())?;
                Ok(5)
            }
            n => {
                w.write_all(&[0xff])?;
                w.write_all(&n.to_le_bytes())?;
                Ok(9)
            }
        }
    }
}

impl Decodable for VarInt {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let first = u8::decode(r)?;
        let n = match first {
            0xff => {
                let n = u64::decode(r)?;
                if n < 0x100000000 {
                    return Err(CodecError::InvalidVarInt);
                }
                n
            }
            0xfe => {
                let n = u32::decode(r)? as u64;
                if n < 0x10000 {
                    return Err(CodecError::InvalidVarInt);
                }
                n
            }
            0xfd => {
                let n = u16::decode(r)? as u64;
                if n < 0xfd {
                    return Err(CodecError::InvalidVarInt);
                }
                n
            }
            n => n as u64,
        };
        Ok(VarInt(n))
    }
}

// ── Vec<u8> with varint-prefixed length ─────────────────────────────────────

impl Encodable for Vec<u8> {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        let len = VarInt(self.len() as u64).encode(w)?;
        w.write_all(self)?;
        Ok(len + self.len())
    }
}

impl Decodable for Vec<u8> {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let VarInt(len) = VarInt::decode(r)?;
        if len > 0x02000000 {
            return Err(CodecError::TooLarge(len));
        }
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf)?;
        Ok(buf)
    }
}

// ── Fixed-size byte arrays ───────────────────────────────────────────────────

impl Encodable for [u8; 32] {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_all(self)?;
        Ok(32)
    }
}

impl Decodable for [u8; 32] {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 32];
        r.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl Encodable for [u8; 4] {
    fn encode<W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_all(self)?;
        Ok(4)
    }
}

impl Decodable for [u8; 4] {
    fn decode<R: Read>(r: &mut R) -> Result<Self> {
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf)?;
        Ok(buf)
    }
}

// ── Vec<T: Encodable/Decodable> ─────────────────────────────────────────────

pub fn encode_list<T: Encodable, W: Write>(list: &[T], w: &mut W) -> Result<usize> {
    let mut n = VarInt(list.len() as u64).encode(w)?;
    for item in list {
        n += item.encode(w)?;
    }
    Ok(n)
}

pub fn decode_list<T: Decodable, R: Read>(r: &mut R) -> Result<Vec<T>> {
    let VarInt(len) = VarInt::decode(r)?;
    if len > 1_000_000 {
        return Err(CodecError::TooLarge(len));
    }
    let mut items = Vec::with_capacity(len as usize);
    for _ in 0..len {
        items.push(T::decode(r)?);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn varint_len() {
        assert_eq!(VarInt(0).len(), 1);
        assert_eq!(VarInt(0xfc).len(), 1);
        assert_eq!(VarInt(0xfd).len(), 3);
        assert_eq!(VarInt(0xffff).len(), 3);
        assert_eq!(VarInt(0x10000).len(), 5);
        assert_eq!(VarInt(0xffffffff).len(), 5);
        assert_eq!(VarInt(0x100000000).len(), 9);
    }

    #[test]
    fn varint_encode_decode_roundtrip() {
        for &n in &[
            0u64,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x10000,
            0xffffffff,
            0x100000000,
            u64::MAX,
        ] {
            let v = VarInt(n);
            let buf = v.encode_to_vec();
            let decoded = VarInt::decode_from_slice(&buf).unwrap();
            assert_eq!(decoded.0, n);
        }
    }

    #[test]
    fn varint_decode_invalid_0xff_small() {
        let buf = [0xff, 0, 0, 0, 0, 0, 0, 0, 0]; // 0 with 0xff prefix
        assert!(VarInt::decode_from_slice(&buf).is_err());
    }

    #[test]
    fn varint_decode_invalid_0xfe_small() {
        let buf = [0xfe, 0xff, 0xff, 0, 0]; // 0xffff < 0x10000
        assert!(VarInt::decode_from_slice(&buf).is_err());
    }

    #[test]
    fn varint_decode_invalid_0xfd_small() {
        let buf = [0xfd, 0xfc, 0]; // 0xfc < 0xfd
        assert!(VarInt::decode_from_slice(&buf).is_err());
    }

    #[test]
    fn primitives_encode_decode() {
        let vals: Vec<u8> = vec![0, 42];
        let b = vals.encode_to_vec();
        assert_eq!(Vec::<u8>::decode_from_slice(&b).unwrap(), vals);

        let v16 = 0x1234u16;
        assert_eq!(u16::decode_from_slice(&v16.encode_to_vec()).unwrap(), v16);
        let v32 = 0x12345678u32;
        assert_eq!(u32::decode_from_slice(&v32.encode_to_vec()).unwrap(), v32);
        let i32v = -1i32;
        assert_eq!(i32::decode_from_slice(&i32v.encode_to_vec()).unwrap(), i32v);
        let v64 = 0x123456789abcdef0u64;
        assert_eq!(u64::decode_from_slice(&v64.encode_to_vec()).unwrap(), v64);
        let i64v = -1i64;
        assert_eq!(i64::decode_from_slice(&i64v.encode_to_vec()).unwrap(), i64v);
    }

    #[test]
    fn vec_u8_too_large() {
        let mut buf = Vec::new();
        VarInt(0x02000001).encode(&mut buf).unwrap();
        assert!(Vec::<u8>::decode_from_slice(&buf).is_err());
    }

    #[test]
    fn decode_list_too_large() {
        let mut buf = Vec::new();
        VarInt(1_000_001).encode(&mut buf).unwrap();
        buf.push(0);
        let mut c = Cursor::new(buf);
        assert!(decode_list::<u8, _>(&mut c).is_err());
    }

    #[test]
    fn encode_decode_list() {
        let list: Vec<u32> = vec![1, 2, 3];
        let mut buf = Vec::new();
        encode_list(&list, &mut buf).unwrap();
        let decoded: Vec<u32> = decode_list(&mut Cursor::new(buf)).unwrap();
        assert_eq!(decoded, list);
    }

    #[test]
    fn array_32_encode_decode() {
        let arr = [7u8; 32];
        let b = arr.encode_to_vec();
        assert_eq!(<[u8; 32]>::decode_from_slice(&b).unwrap(), arr);
    }

    #[test]
    fn array_4_encode_decode() {
        let arr = [1u8, 2, 3, 4];
        let b = arr.encode_to_vec();
        assert_eq!(<[u8; 4]>::decode_from_slice(&b).unwrap(), arr);
    }

    #[test]
    fn encodable_encode_to_vec() {
        let v = 42u8;
        let b = v.encode_to_vec();
        assert_eq!(b, vec![42]);
    }

    #[test]
    fn decode_unexpected_eof() {
        let empty: &[u8] = &[];
        assert!(u32::decode_from_slice(empty).is_err());
    }
}
