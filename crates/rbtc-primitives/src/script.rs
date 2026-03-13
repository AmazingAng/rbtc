use crate::codec::{Decodable, Encodable, VarInt};
use smallvec::SmallVec;
use std::io::{Read, Write};

/// Raw Bitcoin script bytes.
///
/// Uses `SmallVec<[u8; 36]>` internally, matching Bitcoin Core's
/// `prevector<36, uint8_t>`.  Scripts up to 36 bytes (covering P2PKH 25B,
/// P2WPKH 22B, P2TR 34B) are stored inline without a heap allocation.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Script(pub SmallVec<[u8; 36]>);

impl Script {
    pub fn new() -> Self {
        Self(SmallVec::new())
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(SmallVec::from_vec(bytes))
    }

    pub fn from_slice(s: &[u8]) -> Self {
        Self(SmallVec::from_slice(s))
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

    pub fn clear(&mut self) {
        self.0.clear();
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

    /// Returns true if the script is guaranteed to fail at execution,
    /// regardless of the initial stack. Matches Bitcoin Core's
    /// `CScript::IsUnspendable()`: OP_RETURN prefix OR size > MAX_SCRIPT_SIZE.
    pub fn is_unspendable(&self) -> bool {
        use crate::constants::MAX_SCRIPT_SIZE;
        self.is_op_return() || self.0.len() > MAX_SCRIPT_SIZE
    }

    /// Bare multisig: `OP_m <pubkey1> ... <pubkeyn> OP_n OP_CHECKMULTISIG`
    pub fn is_bare_multisig(&self) -> bool {
        let s = &self.0;
        if s.len() < 3 {
            return false;
        }
        // Last byte must be OP_CHECKMULTISIG (0xae)
        if s[s.len() - 1] != 0xae {
            return false;
        }
        // First byte: OP_1..OP_16 (0x51..0x60)
        let m_op = s[0];
        if !(0x51..=0x60).contains(&m_op) {
            return false;
        }
        // Second-to-last byte: OP_1..OP_16 (n)
        let n_op = s[s.len() - 2];
        if !(0x51..=0x60).contains(&n_op) {
            return false;
        }
        let m = (m_op - 0x50) as usize;
        let n = (n_op - 0x50) as usize;
        if m > n {
            return false;
        }
        // Walk pubkeys: each is a 33 or 65-byte push
        let mut pos = 1;
        let mut count = 0usize;
        while pos < s.len() - 2 {
            let push_len = s[pos] as usize;
            if push_len != 33 && push_len != 65 {
                return false;
            }
            pos += 1 + push_len;
            count += 1;
        }
        count == n && pos == s.len() - 2
    }

    /// If this is a bare multisig script, return `(m, n)`.
    /// Returns `None` if the script is not a valid bare multisig.
    pub fn bare_multisig_params(&self) -> Option<(u8, u8)> {
        if !self.is_bare_multisig() {
            return None;
        }
        let m = self.0[0] - 0x50;
        let n = self.0[self.0.len() - 2] - 0x50;
        Some((m, n))
    }

    /// Get the 20-byte hash for P2PKH
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

    /// Detect any witness program (BIP141): OP_n <2..40 bytes>
    /// where n is 0..16 (opcodes 0x00, 0x51..0x60).
    pub fn is_witness_program(&self) -> bool {
        self.witness_version().is_some()
    }

    /// Extract witness version (0-16) and program from a witness scriptPubKey.
    /// Returns None if this is not a valid witness program.
    pub fn witness_version(&self) -> Option<(u8, &[u8])> {
        if self.0.len() < 4 || self.0.len() > 42 {
            return None;
        }
        let version_opcode = self.0[0];
        let version = if version_opcode == 0x00 {
            0u8
        } else if (0x51..=0x60).contains(&version_opcode) {
            version_opcode - 0x50
        } else {
            return None;
        };
        let program_len = self.0[1] as usize;
        if program_len + 2 != self.0.len() || !(2..=40).contains(&program_len) {
            return None;
        }
        Some((version, &self.0[2..]))
    }

    /// Check if the script is push-only (only data pushes, no opcodes > OP_16).
    pub fn is_push_only(&self) -> bool {
        let bytes = &self.0;
        let mut i = 0;
        while i < bytes.len() {
            let op = bytes[i];
            if op > 0x60 {
                return false; // opcode > OP_16
            }
            i += 1;
            match op {
                0x01..=0x4b => i += op as usize,
                0x4c => {
                    if i >= bytes.len() { return false; }
                    let len = bytes[i] as usize;
                    i += 1 + len;
                }
                0x4d => {
                    if i + 1 >= bytes.len() { return false; }
                    let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
                    i += 2 + len;
                }
                0x4e => {
                    if i + 3 >= bytes.len() { return false; }
                    let len = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
                    i += 4 + len;
                }
                _ => {} // OP_0 (0x00), OP_1-OP_16 (0x51-0x60), OP_1NEGATE (0x4f)
            }
        }
        true
    }

    /// Count sigops in this script using legacy (non-accurate) rules.
    pub fn count_sigops(&self) -> usize {
        self.count_sigops_accurate(false)
    }

    /// Count sigops in this script.
    pub fn count_sigops_accurate(&self, accurate: bool) -> usize {
        let mut count = 0usize;
        let mut i = 0;
        let bytes = &self.0;
        let mut last_opcode: Option<u8> = None;
        while i < bytes.len() {
            let op = bytes[i];
            match op {
                0xac | 0xad => count += 1,
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
                        let len = u32::from_le_bytes([
                            bytes[i],
                            bytes[i + 1],
                            bytes[i + 2],
                            bytes[i + 3],
                        ]) as usize;
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
        write!(f, "Script({})", hex::encode(&self.0[..]))
    }
}

impl std::fmt::Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..]))
    }
}

impl Encodable for Script {
    fn encode<W: Write>(&self, w: &mut W) -> crate::codec::Result<usize> {
        let len = VarInt(self.0.len() as u64).encode(w)?;
        w.write_all(&self.0)?;
        Ok(len + self.0.len())
    }
}

impl Decodable for Script {
    fn decode<R: Read>(r: &mut R) -> crate::codec::Result<Self> {
        let VarInt(len) = VarInt::decode(r)?;
        if len > 0x02000000 {
            return Err(crate::codec::CodecError::TooLarge(len));
        }
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf)?;
        Ok(Self(SmallVec::from_vec(buf)))
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
        Script::from_bytes(v)
    }

    fn p2sh_script(script_hash: [u8; 20]) -> Script {
        let mut v = vec![0xa9, 0x14];
        v.extend_from_slice(&script_hash);
        v.push(0x87);
        Script::from_bytes(v)
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
        let s = Script::from_bytes(wpkh);
        assert!(s.is_p2wpkh());
        assert!(s.p2wpkh_pubkey_hash().is_some());

        let mut wsh = vec![0x00, 0x20];
        wsh.extend_from_slice(&[0u8; 32]);
        assert!(Script::from_bytes(wsh).is_p2wsh());
        assert!(Script::from_bytes(vec![0x00, 0x20]).is_p2wsh() == false);

        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        assert!(Script::from_bytes(p2tr).is_p2tr());
        assert!(Script::from_bytes(vec![0x51]).is_p2tr() == false);
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
        let s = Script::from_bytes(wsh);
        assert_eq!(s.p2wsh_script_hash(), Some(&key));

        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&key);
        assert_eq!(Script::from_bytes(p2tr).p2tr_output_key(), Some(&key));
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
        assert_eq!(d.0[..], s.0[..]);
    }

    #[test]
    fn script_debug_display() {
        let s = Script::from_bytes(vec![0xab, 0xcd]);
        let _ = format!("{:?}", s);
        let _ = format!("{}", s);
    }

    #[test]
    fn script_smallvec_inline() {
        // P2PKH (25 bytes) should fit inline in SmallVec<[u8; 36]>
        // Use from_slice to build inline (from_bytes takes a Vec which is already heap-alloc'd)
        let mut raw = vec![0x76u8, 0xa9, 0x14];
        raw.extend_from_slice(&[0u8; 20]);
        raw.extend_from_slice(&[0x88, 0xac]);
        let s = Script::from_slice(&raw);
        assert_eq!(s.len(), 25);
        assert!(!s.0.spilled());
    }

    #[test]
    fn script_is_witness_program() {
        // P2WPKH: OP_0 PUSH20 <20 bytes> — witness v0
        let mut wpkh = vec![0x00, 0x14];
        wpkh.extend_from_slice(&[0u8; 20]);
        let s = Script::from_bytes(wpkh);
        assert!(s.is_witness_program());
        assert_eq!(s.witness_version().unwrap().0, 0);

        // P2WSH: OP_0 PUSH32 <32 bytes> — witness v0
        let mut wsh = vec![0x00, 0x20];
        wsh.extend_from_slice(&[0u8; 32]);
        let s = Script::from_bytes(wsh);
        assert!(s.is_witness_program());
        assert_eq!(s.witness_version().unwrap().0, 0);

        // P2TR: OP_1 PUSH32 <32 bytes> — witness v1
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        let s = Script::from_bytes(p2tr);
        assert!(s.is_witness_program());
        assert_eq!(s.witness_version().unwrap().0, 1);

        // Future witness v16: OP_16 PUSH2 <2 bytes>
        let s = Script::from_bytes(vec![0x60, 0x02, 0xaa, 0xbb]);
        assert!(s.is_witness_program());
        assert_eq!(s.witness_version().unwrap().0, 16);

        // Not a witness program: P2PKH
        let p2pkh = p2pkh_script([0u8; 20]);
        assert!(!p2pkh.is_witness_program());

        // Too short
        assert!(!Script::from_bytes(vec![0x00, 0x01, 0xaa]).is_witness_program());
        // Too long (41 bytes program)
        let mut too_long = vec![0x00, 41];
        too_long.extend_from_slice(&[0u8; 41]);
        assert!(!Script::from_bytes(too_long).is_witness_program());
    }

    #[test]
    fn script_is_push_only() {
        // Empty script
        assert!(Script::new().is_push_only());
        // OP_0 OP_1 PUSH1 <byte>
        assert!(Script::from_bytes(vec![0x00, 0x51, 0x01, 0xaa]).is_push_only());
        // OP_CHECKSIG (0xac > 0x60) — not push-only
        assert!(!Script::from_bytes(vec![0xac]).is_push_only());
        // OP_DUP (0x76 > 0x60) — not push-only
        assert!(!Script::from_bytes(vec![0x76]).is_push_only());
    }
}
