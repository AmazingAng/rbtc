use crate::codec::{Decodable, Encodable};
use std::io::{Read, Write};

/// Raw Bitcoin script bytes
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Script(pub Vec<u8>);

impl Script {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25
            && self.0[0] == 0x76  // OP_DUP
            && self.0[1] == 0xa9  // OP_HASH160
            && self.0[2] == 0x14  // push 20 bytes
            && self.0[23] == 0x88 // OP_EQUALVERIFY
            && self.0[24] == 0xac // OP_CHECKSIG
    }

    /// P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23
            && self.0[0] == 0xa9  // OP_HASH160
            && self.0[1] == 0x14  // push 20 bytes
            && self.0[22] == 0x87 // OP_EQUAL
    }

    /// P2WPKH: OP_0 <20 bytes>
    pub fn is_p2wpkh(&self) -> bool {
        self.0.len() == 22 && self.0[0] == 0x00 && self.0[1] == 0x14
    }

    /// P2WSH: OP_0 <32 bytes>
    pub fn is_p2wsh(&self) -> bool {
        self.0.len() == 34 && self.0[0] == 0x00 && self.0[1] == 0x20
    }

    /// P2TR: OP_1 <32 bytes> (Taproot, BIP341)
    pub fn is_p2tr(&self) -> bool {
        self.0.len() == 34 && self.0[0] == 0x51 && self.0[1] == 0x20
    }

    /// OP_RETURN (unspendable data output)
    pub fn is_op_return(&self) -> bool {
        !self.0.is_empty() && self.0[0] == 0x6a
    }

    /// Get the 20-byte hash for P2PKH/P2SH
    pub fn p2pkh_pubkey_hash(&self) -> Option<&[u8; 20]> {
        if self.is_p2pkh() {
            Some(self.0[3..23].try_into().unwrap())
        } else {
            None
        }
    }

    pub fn p2sh_script_hash(&self) -> Option<&[u8; 20]> {
        if self.is_p2sh() {
            Some(self.0[2..22].try_into().unwrap())
        } else {
            None
        }
    }

    pub fn p2wpkh_pubkey_hash(&self) -> Option<&[u8; 20]> {
        if self.is_p2wpkh() {
            Some(self.0[2..22].try_into().unwrap())
        } else {
            None
        }
    }

    pub fn p2wsh_script_hash(&self) -> Option<&[u8; 32]> {
        if self.is_p2wsh() {
            Some(self.0[2..34].try_into().unwrap())
        } else {
            None
        }
    }

    pub fn p2tr_output_key(&self) -> Option<&[u8; 32]> {
        if self.is_p2tr() {
            Some(self.0[2..34].try_into().unwrap())
        } else {
            None
        }
    }

    /// Count sigops in this script using legacy (non-accurate) rules.
    pub fn count_sigops(&self) -> usize {
        self.count_sigops_accurate(false)
    }

    /// Count sigops in this script.
    ///
    /// When `accurate` is true, CHECKMULTISIG counts as OP_N (1..16) when
    /// immediately preceded by OP_1..OP_16, matching Core's accurate counting
    /// used by P2SH/P2WSH paths.
    pub fn count_sigops_accurate(&self, accurate: bool) -> usize {
        let mut count = 0usize;
        let mut i = 0;
        let bytes = &self.0;
        let mut last_opcode: Option<u8> = None;
        while i < bytes.len() {
            let op = bytes[i];
            match op {
                // OP_CHECKSIG / OP_CHECKSIGVERIFY
                0xac | 0xad => count += 1,
                // OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
                0xae | 0xaf => {
                    if accurate {
                        if let Some(prev) = last_opcode {
                            if (0x51..=0x60).contains(&prev) {
                                count += (prev - 0x50) as usize;
                            } else {
                                count += 20;
                            }
                        } else {
                            count += 20;
                        }
                    } else {
                        count += 20;
                    }
                }
                // data push opcodes – skip the data
                0x01..=0x4b => i += op as usize,
                0x4c => {
                    i += 1;
                    if i < bytes.len() {
                        i += bytes[i] as usize;
                    }
                }
                0x4d => {
                    i += 1;
                    if i + 1 < bytes.len() {
                        let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
                        i += 1 + len;
                    }
                }
                0x4e => {
                    i += 1;
                    if i + 3 < bytes.len() {
                        let len = u32::from_le_bytes([bytes[i], bytes[i+1], bytes[i+2], bytes[i+3]]) as usize;
                        i += 3 + len;
                    }
                }
                _ => {}
            }
            last_opcode = Some(op);
            i += 1;
        }
        count
    }
}

impl std::fmt::Debug for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Script({})", hex::encode(&self.0))
    }
}

impl std::fmt::Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Encodable for Script {
    fn encode<W: Write>(&self, w: &mut W) -> crate::codec::Result<usize> {
        self.0.encode(w)
    }
}

impl Decodable for Script {
    fn decode<R: Read>(r: &mut R) -> crate::codec::Result<Self> {
        Ok(Self(Vec::<u8>::decode(r)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Decodable, Encodable};

    fn p2pkh_script(pubkey_hash: [u8; 20]) -> Script {
        let mut v = vec![0x76, 0xa9, 0x14];
        v.extend_from_slice(&pubkey_hash);
        v.extend_from_slice(&[0x88, 0xac]);
        Script(v)
    }

    fn p2sh_script(script_hash: [u8; 20]) -> Script {
        let mut v = vec![0xa9, 0x14];
        v.extend_from_slice(&script_hash);
        v.push(0x87);
        Script(v)
    }

    #[test]
    fn script_new_empty() {
        let s = Script::new();
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
        assert_eq!(s.as_bytes(), &[]);
    }

    #[test]
    fn script_from_bytes() {
        let s = Script::from_bytes(vec![1, 2, 3]);
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
        assert_eq!(s.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn script_default() {
        let s = Script::default();
        assert!(s.is_empty());
    }

    #[test]
    fn script_is_p2pkh() {
        let mut h = [0u8; 20];
        h[0] = 1;
        let s = p2pkh_script(h);
        assert!(s.is_p2pkh());
        assert_eq!(s.p2pkh_pubkey_hash(), Some(&h));
        assert!(Script::from_bytes(vec![0x76]).is_p2pkh() == false);
        let mut bad = p2pkh_script(h);
        bad.0[0] = 0;
        assert!(!bad.is_p2pkh());
    }

    #[test]
    fn script_is_p2sh() {
        let h = [2u8; 20];
        let s = p2sh_script(h);
        assert!(s.is_p2sh());
        assert_eq!(s.p2sh_script_hash(), Some(&h));
        assert!(Script::from_bytes(vec![0xa9, 0x14]).is_p2sh() == false);
    }

    #[test]
    fn script_is_p2wpkh_p2wsh_p2tr() {
        let mut wpkh = vec![0x00, 0x14];
        wpkh.extend_from_slice(&[0u8; 20]);
        let s = Script(wpkh);
        assert!(s.is_p2wpkh());
        assert!(s.p2wpkh_pubkey_hash().is_some());

        let mut wsh = vec![0x00, 0x20];
        wsh.extend_from_slice(&[0u8; 32]);
        assert!(Script(wsh).is_p2wsh());
        assert!(Script(vec![0x00, 0x20]).is_p2wsh() == false);

        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        assert!(Script(p2tr).is_p2tr());
        assert!(Script(vec![0x51]).is_p2tr() == false);
    }

    #[test]
    fn script_is_op_return() {
        assert!(Script::from_bytes(vec![0x6a, 1, 2]).is_op_return());
        assert!(!Script::new().is_op_return());
        assert!(!Script::from_bytes(vec![0x00]).is_op_return());
    }

    #[test]
    fn script_p2wsh_p2tr_output_key() {
        let mut wsh = vec![0x00, 0x20];
        let key = [5u8; 32];
        wsh.extend_from_slice(&key);
        let s = Script(wsh);
        assert_eq!(s.p2wsh_script_hash(), Some(&key));

        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&key);
        assert_eq!(Script(p2tr).p2tr_output_key(), Some(&key));
    }

    #[test]
    fn script_count_sigops() {
        assert_eq!(Script::new().count_sigops(), 0);
        let s = Script::from_bytes(vec![0xac]);
        assert_eq!(s.count_sigops(), 1);
        let s = Script::from_bytes(vec![0xad]);
        assert_eq!(s.count_sigops(), 1);
        let s = Script::from_bytes(vec![0xae]);
        assert_eq!(s.count_sigops(), 20);
        let s = Script::from_bytes(vec![0x01, 0x00, 0xac]);
        assert_eq!(s.count_sigops(), 1);
        let s = Script::from_bytes(vec![0x52, 0xae]);
        assert_eq!(s.count_sigops_accurate(true), 2);
        let s = Script::from_bytes(vec![0xae]);
        assert_eq!(s.count_sigops_accurate(true), 20);
    }

    #[test]
    fn script_encode_decode() {
        let s = Script::from_bytes(vec![1, 2, 3]);
        let buf = s.encode_to_vec();
        let d = Script::decode_from_slice(&buf).unwrap();
        assert_eq!(d.0, s.0);
    }

    #[test]
    fn script_debug_display() {
        let s = Script::from_bytes(vec![0xab, 0xcd]);
        let _ = format!("{:?}", s);
        let _ = format!("{}", s);
    }
}
