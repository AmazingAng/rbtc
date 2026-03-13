//! MuHash3072 — a rolling hash for UTXO set verification.
//!
//! MuHash is a set-hashing algorithm that supports adding and removing elements
//! in any order while maintaining a running hash. It works by representing the
//! hash as a fraction (numerator/denominator) of 3072-bit numbers modulo the
//! prime 2^3072 - 1103717.
//!
//! Reference: Bitcoin Core `src/crypto/muhash.{h,cpp}`

use crate::sha256;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rbtc_primitives::hash::Hash256;

/// The prime modulus is 2^3072 - MAX_PRIME_DIFF.
const MAX_PRIME_DIFF: u64 = 1103717;

/// Number of 64-bit limbs in a 3072-bit number.
const LIMBS: usize = 48;

/// Byte size of a 3072-bit number.
const BYTE_SIZE: usize = 384;

/// Number of signed limbs used in the divsteps-based inverse.
/// Each signed limb is 62 bits. 50 * 62 = 3100 > 3072.
const SIGNED_LIMB_SIZE: usize = 62;
const SIGNED_LIMBS: usize = 50;
const MAX_SIGNED_LIMB: u64 = (1u64 << SIGNED_LIMB_SIZE) - 1;
const FINAL_LIMB_POSITION: usize = 3072 / SIGNED_LIMB_SIZE; // = 49
const FINAL_LIMB_MODULUS_BITS: usize = 3072 % SIGNED_LIMB_SIZE; // = 42

/// The modular inverse of the modulus mod (2^62), used in divsteps.
/// Computed as: inverse of (2^3072 - 1103717) mod 2^62.
const MODULUS_INVERSE: u64 = 0x70a1421da087d93;

/// A 3072-bit number stored as 48 little-endian u64 limbs.
#[derive(Clone, Debug)]
pub struct Num3072 {
    limbs: [u64; LIMBS],
}

impl PartialEq for Num3072 {
    fn eq(&self, other: &Self) -> bool {
        self.limbs == other.limbs
    }
}
impl Eq for Num3072 {}

impl Num3072 {
    /// Create a Num3072 with value 1.
    pub fn one() -> Self {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = 1;
        Num3072 { limbs }
    }

    /// Create a Num3072 from 384 bytes (little-endian).
    pub fn from_bytes(data: &[u8; BYTE_SIZE]) -> Self {
        let mut limbs = [0u64; LIMBS];
        for i in 0..LIMBS {
            limbs[i] = u64::from_le_bytes(data[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        Num3072 { limbs }
    }

    /// Serialize to 384 bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; BYTE_SIZE] {
        let mut out = [0u8; BYTE_SIZE];
        for i in 0..LIMBS {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        out
    }

    /// Check if the value is >= the modulus (2^3072 - MAX_PRIME_DIFF).
    fn is_overflow(&self) -> bool {
        if self.limbs[0] <= u64::MAX - MAX_PRIME_DIFF {
            return false;
        }
        for i in 1..LIMBS {
            if self.limbs[i] != u64::MAX {
                return false;
            }
        }
        true
    }

    /// Reduce by adding MAX_PRIME_DIFF (equivalent to subtracting the modulus).
    fn full_reduce(&mut self) {
        let mut c0: u64 = MAX_PRIME_DIFF;
        let mut c1: u64 = 0;
        for i in 0..LIMBS {
            // addnextract2: [c0,c1] += limbs[i], then extract bottom into limbs[i]
            let mut c2: u64 = 0;
            let new_c0 = c0.wrapping_add(self.limbs[i]);
            if new_c0 < c0 {
                c1 = c1.wrapping_add(1);
                if c1 == 0 {
                    c2 = 1;
                }
            }
            self.limbs[i] = new_c0;
            c0 = c1;
            c1 = c2;
        }
    }

    /// Multiply self by `a` modulo (2^3072 - MAX_PRIME_DIFF).
    pub fn multiply(&mut self, a: &Num3072) {
        let mut c0: u64 = 0;
        let mut c1: u64 = 0;
        let mut c2: u64 = 0;
        let mut tmp = [0u64; LIMBS];

        // Compute limbs 0..N-2 of self*a into tmp, including one reduction.
        for j in 0..LIMBS - 1 {
            let mut d2: u64 = 0;
            // d = self.limbs[1+j] * a.limbs[LIMBS-1]
            let (mut d0, mut d1) = mul_wide(self.limbs[1 + j], a.limbs[LIMBS + j - (1 + j)]);
            for i in (2 + j)..LIMBS {
                muladd3(&mut d0, &mut d1, &mut d2, self.limbs[i], a.limbs[LIMBS + j - i]);
            }
            // [c0,c1,c2] += MAX_PRIME_DIFF * [d0,d1,d2]
            mulnadd3(&mut c0, &mut c1, &mut c2, &mut d0, &mut d1, &mut d2, MAX_PRIME_DIFF);
            for i in 0..=j {
                muladd3(&mut c0, &mut c1, &mut c2, self.limbs[i], a.limbs[j - i]);
            }
            tmp[j] = c0;
            c0 = c1;
            c1 = c2;
            c2 = 0;
        }

        // Compute limb N-1 of self*a into tmp.
        debug_assert!(c2 == 0);
        for i in 0..LIMBS {
            muladd3(&mut c0, &mut c1, &mut c2, self.limbs[i], a.limbs[LIMBS - 1 - i]);
        }
        tmp[LIMBS - 1] = c0;
        c0 = c1;
        c1 = c2;

        // Second reduction: multiply carry by MAX_PRIME_DIFF and add tmp.
        muln2(&mut c0, &mut c1, MAX_PRIME_DIFF);
        for j in 0..LIMBS {
            // addnextract2
            let mut c2_local: u64 = 0;
            let old_c0 = c0;
            c0 = c0.wrapping_add(tmp[j]);
            if c0 < old_c0 {
                let old_c1 = c1;
                c1 = c1.wrapping_add(1);
                if c1 == 0 {
                    c2_local = 1;
                }
                let _ = old_c1;
            }
            self.limbs[j] = c0;
            c0 = c1;
            c1 = c2_local;
        }

        debug_assert!(c1 == 0);
        debug_assert!(c0 == 0 || c0 == 1);

        if self.is_overflow() {
            self.full_reduce();
        }
        if c0 != 0 {
            self.full_reduce();
        }
    }

    /// Compute the modular inverse using the safegcd/divsteps algorithm.
    /// Reference: Bitcoin Core's Num3072::GetInverse()
    pub fn get_inverse(&self) -> Num3072 {
        let mut d = SignedNum3072::zero();
        let mut e = SignedNum3072::zero();
        e.limbs[0] = 1;

        // f = modulus = 2^3072 - MAX_PRIME_DIFF
        let mut f = SignedNum3072::zero();
        f.limbs[0] = -(MAX_PRIME_DIFF as i64);
        f.limbs[FINAL_LIMB_POSITION] = 1i64 << FINAL_LIMB_MODULUS_BITS;

        let mut g = SignedNum3072::from_num3072(self);
        let mut len = SIGNED_LIMBS;
        let mut eta: i64 = -1;

        loop {
            let t = compute_divstep_matrix(eta, f.limbs[0] as u64, g.limbs[0] as u64);
            eta = t.eta;
            update_fg(&mut f, &mut g, &t.matrix, len);
            update_de(&mut d, &mut e, &t.matrix);

            // Check if g is zero.
            if g.limbs[0] == 0 {
                let mut cond: i64 = 0;
                for j in 1..len {
                    cond |= g.limbs[j];
                }
                if cond == 0 {
                    break;
                }
            }

            // Check if we can shrink len.
            let fn_val = f.limbs[len - 1];
            let gn_val = g.limbs[len - 1];
            let mut cond = ((len as i64) - 2) >> 63;
            cond |= fn_val ^ (fn_val >> 63);
            cond |= gn_val ^ (gn_val >> 63);
            if cond == 0 {
                f.limbs[len - 2] |=
                    ((f.limbs[len - 1] as u64) << SIGNED_LIMB_SIZE) as i64;
                g.limbs[len - 2] |=
                    ((g.limbs[len - 1] as u64) << SIGNED_LIMB_SIZE) as i64;
                len -= 1;
            }
        }

        // f should be +/-1 now. Normalize d, negating if f is negative.
        let negate = f.limbs[len - 1] >> 63 != 0;
        d.normalize(negate);
        d.to_num3072()
    }

    /// Divide self by `a` modulo the prime.
    pub fn divide(&mut self, a: &Num3072) {
        if self.is_overflow() {
            self.full_reduce();
        }

        let inv = if a.is_overflow() {
            let mut b = a.clone();
            b.full_reduce();
            b.get_inverse()
        } else {
            a.get_inverse()
        };

        self.multiply(&inv);
        if self.is_overflow() {
            self.full_reduce();
        }
    }
}

// --- Signed 3072-bit number for divsteps inverse ---

#[derive(Clone)]
struct SignedNum3072 {
    limbs: [i64; SIGNED_LIMBS],
}

impl SignedNum3072 {
    fn zero() -> Self {
        SignedNum3072 {
            limbs: [0i64; SIGNED_LIMBS],
        }
    }

    /// Convert from Num3072 to signed limb representation.
    /// Repack 48x64-bit limbs into 50x62-bit limbs.
    fn from_num3072(n: &Num3072) -> Self {
        let mut out = Self::zero();
        let mut c: u128 = 0;
        let mut b: usize = 0;
        let mut outpos: usize = 0;
        for i in 0..LIMBS {
            c += (n.limbs[i] as u128) << b;
            b += 64;
            while b >= SIGNED_LIMB_SIZE {
                out.limbs[outpos] = (c as u64 & MAX_SIGNED_LIMB) as i64;
                outpos += 1;
                c >>= SIGNED_LIMB_SIZE;
                b -= SIGNED_LIMB_SIZE;
            }
        }
        debug_assert!(outpos == SIGNED_LIMBS - 1);
        out.limbs[SIGNED_LIMBS - 1] = c as i64;
        out
    }

    /// Convert back to Num3072 from signed limb representation.
    /// Input must be in range 0..modulus-1.
    fn to_num3072(&self) -> Num3072 {
        let mut out = Num3072 { limbs: [0u64; LIMBS] };
        let mut c: u128 = 0;
        let mut b: usize = 0;
        let mut outpos: usize = 0;
        for i in 0..SIGNED_LIMBS {
            c += (self.limbs[i] as u64 as u128) << b;
            b += SIGNED_LIMB_SIZE;
            if b >= 64 {
                out.limbs[outpos] = c as u64;
                outpos += 1;
                c >>= 64;
                b -= 64;
            }
        }
        debug_assert!(outpos == LIMBS);
        out
    }

    /// Normalize: reduce modulo the prime, optionally negating.
    fn normalize(&mut self, negate: bool) {
        // Add modulus if negative.
        let cond_add = self.limbs[SIGNED_LIMBS - 1] >> 63; // -1 if negative, 0 otherwise
        self.limbs[0] =
            self.limbs[0].wrapping_add((-(MAX_PRIME_DIFF as i64)) & cond_add);
        self.limbs[FINAL_LIMB_POSITION] = self.limbs[FINAL_LIMB_POSITION]
            .wrapping_add((1i64 << FINAL_LIMB_MODULUS_BITS) & cond_add);

        // Negate all limbs if negate is true.
        let cond_negate: i64 = if negate { -1 } else { 0 };
        for i in 0..SIGNED_LIMBS {
            self.limbs[i] = (self.limbs[i] ^ cond_negate).wrapping_sub(cond_negate);
        }

        // Carry propagation.
        for i in 0..SIGNED_LIMBS - 1 {
            self.limbs[i + 1] =
                self.limbs[i + 1].wrapping_add(self.limbs[i] >> SIGNED_LIMB_SIZE);
            self.limbs[i] &= MAX_SIGNED_LIMB as i64;
        }

        // Add modulus again if still negative.
        let cond_add = self.limbs[SIGNED_LIMBS - 1] >> 63;
        self.limbs[0] =
            self.limbs[0].wrapping_add((-(MAX_PRIME_DIFF as i64)) & cond_add);
        self.limbs[FINAL_LIMB_POSITION] = self.limbs[FINAL_LIMB_POSITION]
            .wrapping_add((1i64 << FINAL_LIMB_MODULUS_BITS) & cond_add);

        // Carry again.
        for i in 0..SIGNED_LIMBS - 1 {
            self.limbs[i + 1] =
                self.limbs[i + 1].wrapping_add(self.limbs[i] >> SIGNED_LIMB_SIZE);
            self.limbs[i] &= MAX_SIGNED_LIMB as i64;
        }
    }
}

// --- Divstep matrix ---

struct DivstepResult {
    eta: i64,
    matrix: SignedMatrix,
}

#[derive(Clone, Copy)]
struct SignedMatrix {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// Table of -1/(2*i+1) mod 256 for i in 0..128.
const NEGINV256: [u8; 128] = [
    0xFF, 0x55, 0x33, 0x49, 0xC7, 0x5D, 0x3B, 0x11, 0x0F, 0xE5, 0xC3, 0x59,
    0xD7, 0xED, 0xCB, 0x21, 0x1F, 0x75, 0x53, 0x69, 0xE7, 0x7D, 0x5B, 0x31,
    0x2F, 0x05, 0xE3, 0x79, 0xF7, 0x0D, 0xEB, 0x41, 0x3F, 0x95, 0x73, 0x89,
    0x07, 0x9D, 0x7B, 0x51, 0x4F, 0x25, 0x03, 0x99, 0x17, 0x2D, 0x0B, 0x61,
    0x5F, 0xB5, 0x93, 0xA9, 0x27, 0xBD, 0x9B, 0x71, 0x6F, 0x45, 0x23, 0xB9,
    0x37, 0x4D, 0x2B, 0x81, 0x7F, 0xD5, 0xB3, 0xC9, 0x47, 0xDD, 0xBB, 0x91,
    0x8F, 0x65, 0x43, 0xD9, 0x57, 0x6D, 0x4B, 0xA1, 0x9F, 0xF5, 0xD3, 0xE9,
    0x67, 0xFD, 0xDB, 0xB1, 0xAF, 0x85, 0x63, 0xF9, 0x77, 0x8D, 0x6B, 0xC1,
    0xBF, 0x15, 0xF3, 0x09, 0x87, 0x1D, 0xFB, 0xD1, 0xCF, 0xA5, 0x83, 0x19,
    0x97, 0xAD, 0x8B, 0xE1, 0xDF, 0x35, 0x13, 0x29, 0xA7, 0x3D, 0x1B, 0xF1,
    0xEF, 0xC5, 0xA3, 0x39, 0xB7, 0xCD, 0xAB, 0x01,
];

/// Compute the divstep transformation matrix for SIGNED_LIMB_SIZE iterations.
fn compute_divstep_matrix(mut eta: i64, f_in: u64, g_in: u64) -> DivstepResult {
    let mut f = f_in;
    let mut g = g_in;
    let mut u: u64 = 1;
    let mut v: u64 = 0;
    let mut q: u64 = 0;
    let mut r: u64 = 1;
    let mut i = SIGNED_LIMB_SIZE as u32;

    loop {
        let zeros = (g | (u64::MAX << i)).trailing_zeros();
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros as i64;
        i -= zeros;
        if i == 0 {
            break;
        }
        if eta < 0 {
            eta = -eta;
            std::mem::swap(&mut f, &mut g);
            g = g.wrapping_neg();
            std::mem::swap(&mut u, &mut q);
            q = q.wrapping_neg();
            std::mem::swap(&mut v, &mut r);
            r = r.wrapping_neg();
        }
        let limit = std::cmp::min((eta + 1) as u32, i);
        let m = (u64::MAX >> (64 - limit)) & 255;
        let w = (g.wrapping_mul(NEGINV256[((f >> 1) & 127) as usize] as u64)) & m;
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
    }

    DivstepResult {
        eta,
        matrix: SignedMatrix {
            u: u as i64,
            v: v as i64,
            q: q as i64,
            r: r as i64,
        },
    }
}

/// Apply matrix t/2^SIGNED_LIMB_SIZE to [d,e] mod modulus.
fn update_de(d: &mut SignedNum3072, e: &mut SignedNum3072, t: &SignedMatrix) {
    let u = t.u;
    let v = t.v;
    let q = t.q;
    let r = t.r;

    let sd = d.limbs[SIGNED_LIMBS - 1] >> 63;
    let se = e.limbs[SIGNED_LIMBS - 1] >> 63;
    let mut md: i64 = (u & sd) + (v & se);
    let mut me: i64 = (q & sd) + (r & se);

    let di = d.limbs[0];
    let ei = e.limbs[0];
    let mut cd: i128 = (u as i128) * (di as i128) + (v as i128) * (ei as i128);
    let mut ce: i128 = (q as i128) * (di as i128) + (r as i128) * (ei as i128);

    // Correct md,me so that result has SIGNED_LIMB_SIZE zero bottom bits.
    md = md.wrapping_sub(
        ((MODULUS_INVERSE.wrapping_mul(cd as u64)).wrapping_add(md as u64) & MAX_SIGNED_LIMB)
            as i64,
    );
    me = me.wrapping_sub(
        ((MODULUS_INVERSE.wrapping_mul(ce as u64)).wrapping_add(me as u64) & MAX_SIGNED_LIMB)
            as i64,
    );

    cd -= (MAX_PRIME_DIFF as i128) * (md as i128);
    ce -= (MAX_PRIME_DIFF as i128) * (me as i128);

    debug_assert!((cd as u64) & MAX_SIGNED_LIMB == 0);
    debug_assert!((ce as u64) & MAX_SIGNED_LIMB == 0);
    cd >>= SIGNED_LIMB_SIZE;
    ce >>= SIGNED_LIMB_SIZE;

    for i in 1..SIGNED_LIMBS - 1 {
        let di = d.limbs[i];
        let ei = e.limbs[i];
        cd += (u as i128) * (di as i128) + (v as i128) * (ei as i128);
        ce += (q as i128) * (di as i128) + (r as i128) * (ei as i128);
        d.limbs[i - 1] = (cd as i64) & (MAX_SIGNED_LIMB as i64);
        cd >>= SIGNED_LIMB_SIZE;
        e.limbs[i - 1] = (ce as i64) & (MAX_SIGNED_LIMB as i64);
        ce >>= SIGNED_LIMB_SIZE;
    }

    let di = d.limbs[SIGNED_LIMBS - 1];
    let ei = e.limbs[SIGNED_LIMBS - 1];
    cd += (u as i128) * (di as i128) + (v as i128) * (ei as i128);
    ce += (q as i128) * (di as i128) + (r as i128) * (ei as i128);
    cd += (md as i128) << FINAL_LIMB_MODULUS_BITS;
    ce += (me as i128) << FINAL_LIMB_MODULUS_BITS;
    d.limbs[SIGNED_LIMBS - 2] = (cd as i64) & (MAX_SIGNED_LIMB as i64);
    cd >>= SIGNED_LIMB_SIZE;
    e.limbs[SIGNED_LIMBS - 2] = (ce as i64) & (MAX_SIGNED_LIMB as i64);
    ce >>= SIGNED_LIMB_SIZE;
    d.limbs[SIGNED_LIMBS - 1] = cd as i64;
    e.limbs[SIGNED_LIMBS - 1] = ce as i64;
}

/// Apply matrix t/2^SIGNED_LIMB_SIZE to [f,g].
fn update_fg(
    f: &mut SignedNum3072,
    g: &mut SignedNum3072,
    t: &SignedMatrix,
    len: usize,
) {
    let u = t.u;
    let v = t.v;
    let q = t.q;
    let r = t.r;

    let fi = f.limbs[0];
    let gi = g.limbs[0];
    let mut cf: i128 = (u as i128) * (fi as i128) + (v as i128) * (gi as i128);
    let mut cg: i128 = (q as i128) * (fi as i128) + (r as i128) * (gi as i128);

    debug_assert!((cf as u64) & MAX_SIGNED_LIMB == 0);
    debug_assert!((cg as u64) & MAX_SIGNED_LIMB == 0);
    cf >>= SIGNED_LIMB_SIZE;
    cg >>= SIGNED_LIMB_SIZE;

    for i in 1..len {
        let fi = f.limbs[i];
        let gi = g.limbs[i];
        cf += (u as i128) * (fi as i128) + (v as i128) * (gi as i128);
        cg += (q as i128) * (fi as i128) + (r as i128) * (gi as i128);
        f.limbs[i - 1] = (cf as i64) & (MAX_SIGNED_LIMB as i64);
        cf >>= SIGNED_LIMB_SIZE;
        g.limbs[i - 1] = (cg as i64) & (MAX_SIGNED_LIMB as i64);
        cg >>= SIGNED_LIMB_SIZE;
    }

    f.limbs[len - 1] = cf as i64;
    g.limbs[len - 1] = cg as i64;
}

// --- Arithmetic helpers (inline equivalents of the C++ helpers) ---

/// 64x64 -> 128 bit multiplication.
#[inline(always)]
fn mul_wide(a: u64, b: u64) -> (u64, u64) {
    let t = (a as u128) * (b as u128);
    (t as u64, (t >> 64) as u64)
}

/// [c0,c1,c2] += a * b
#[inline(always)]
fn muladd3(c0: &mut u64, c1: &mut u64, c2: &mut u64, a: u64, b: u64) {
    let t = (a as u128) * (b as u128);
    let tl = t as u64;
    let th = (t >> 64) as u64;

    *c0 = c0.wrapping_add(tl);
    let carry = if *c0 < tl { 1u64 } else { 0u64 };
    let th = th.wrapping_add(carry);
    *c1 = c1.wrapping_add(th);
    if *c1 < th {
        *c2 = c2.wrapping_add(1);
    }
}

/// [c0,c1,c2] += n * [d0,d1,d2]
#[inline(always)]
fn mulnadd3(
    c0: &mut u64,
    c1: &mut u64,
    c2: &mut u64,
    d0: &mut u64,
    d1: &mut u64,
    d2: &mut u64,
    n: u64,
) {
    let t = (*d0 as u128) * (n as u128) + (*c0 as u128);
    *c0 = t as u64;
    let t = (t >> 64) + (*d1 as u128) * (n as u128) + (*c1 as u128);
    *c1 = t as u64;
    let t = (t >> 64) + (*d2 as u128) * (n as u128);
    *c2 = t as u64;
}

/// [c0,c1] *= n
#[inline(always)]
fn muln2(c0: &mut u64, c1: &mut u64, n: u64) {
    let t = (*c0 as u128) * (n as u128);
    *c0 = t as u64;
    let t = (t >> 64) + (*c1 as u128) * (n as u128);
    *c1 = t as u64;
}

// --- Element construction: SHA256 -> ChaCha20 expansion -> Num3072 ---

/// Hash arbitrary data to a Num3072 element.
/// SHA256(data) is used as a ChaCha20 key with zero nonce to generate 384 bytes.
fn data_to_num3072(data: &[u8]) -> Num3072 {
    let hash = sha256(data);
    let mut buf = [0u8; BYTE_SIZE];

    // ChaCha20 with key = SHA256(data), nonce = 0, counter = 0
    // Generate 384 bytes of keystream (XOR with zeros = keystream).
    let key = chacha20::Key::from_slice(&hash.0);
    let nonce = chacha20::Nonce::from_slice(&[0u8; 12]);
    let mut cipher = ChaCha20::new(key, nonce);
    cipher.apply_keystream(&mut buf);

    Num3072::from_bytes(&buf)
}

/// MuHash3072 — a rolling hash for UTXO set verification.
///
/// Maintains a running numerator and denominator. Elements are multiplied
/// into the numerator on insert, and into the denominator on remove.
/// On finalize, the result is numerator/denominator mod prime, then SHA256'd.
#[derive(Clone)]
pub struct MuHash3072 {
    numerator: Num3072,
    denominator: Num3072,
}

impl MuHash3072 {
    /// Create a new empty MuHash (identity element).
    pub fn new() -> Self {
        MuHash3072 {
            numerator: Num3072::one(),
            denominator: Num3072::one(),
        }
    }

    /// Create a MuHash from a single element.
    pub fn from_data(data: &[u8]) -> Self {
        MuHash3072 {
            numerator: data_to_num3072(data),
            denominator: Num3072::one(),
        }
    }

    /// Insert an element into the set.
    pub fn insert(&mut self, data: &[u8]) {
        let elem = data_to_num3072(data);
        self.numerator.multiply(&elem);
    }

    /// Remove an element from the set.
    pub fn remove(&mut self, data: &[u8]) {
        let elem = data_to_num3072(data);
        self.denominator.multiply(&elem);
    }

    /// Combine two MuHash values (union of sets).
    pub fn combine(&mut self, other: &MuHash3072) {
        self.numerator.multiply(&other.numerator);
        self.denominator.multiply(&other.denominator);
    }

    /// Remove another MuHash's set from this one (set difference).
    pub fn remove_set(&mut self, other: &MuHash3072) {
        self.numerator.multiply(&other.denominator);
        self.denominator.multiply(&other.numerator);
    }

    /// Finalize the hash into a 32-byte Hash256.
    /// Computes numerator / denominator mod prime, then SHA256.
    pub fn finalize(&self) -> Hash256 {
        let mut result = self.numerator.clone();
        result.divide(&self.denominator);

        let bytes = result.to_bytes();
        sha256(&bytes)
    }
}

impl Default for MuHash3072 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num3072_one_is_identity() {
        let mut a = Num3072::one();
        let one = Num3072::one();
        a.multiply(&one);
        assert_eq!(a, one);
    }

    #[test]
    fn num3072_multiply_inverse() {
        // Create a non-trivial element, compute its inverse, multiply.
        // Result should be 1.
        let data = [42u8; 32];
        let elem = data_to_num3072(&data);
        let inv = elem.get_inverse();
        let mut result = elem.clone();
        result.multiply(&inv);
        // After multiply by inverse, should be 1.
        assert_eq!(result, Num3072::one());
    }

    #[test]
    fn muhash_empty_finalize_deterministic() {
        let a = MuHash3072::new();
        let b = MuHash3072::new();
        assert_eq!(a.finalize(), b.finalize());
    }

    #[test]
    fn muhash_single_element_deterministic() {
        let mut a = MuHash3072::new();
        let mut b = MuHash3072::new();
        a.insert(b"hello");
        b.insert(b"hello");
        assert_eq!(a.finalize(), b.finalize());
    }

    #[test]
    fn muhash_insert_remove_identity() {
        let mut h = MuHash3072::new();
        let empty_hash = h.finalize();

        h.insert(b"test element");
        assert_ne!(h.finalize(), empty_hash);

        h.remove(b"test element");
        assert_eq!(h.finalize(), empty_hash);
    }

    #[test]
    fn muhash_commutative() {
        let mut h1 = MuHash3072::new();
        h1.insert(b"aaa");
        h1.insert(b"bbb");
        h1.insert(b"ccc");

        let mut h2 = MuHash3072::new();
        h2.insert(b"ccc");
        h2.insert(b"aaa");
        h2.insert(b"bbb");

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn muhash_combine_equals_sequential() {
        let mut h1 = MuHash3072::new();
        h1.insert(b"aaa");
        h1.insert(b"bbb");

        let mut ha = MuHash3072::new();
        ha.insert(b"aaa");
        let mut hb = MuHash3072::new();
        hb.insert(b"bbb");
        ha.combine(&hb);

        assert_eq!(h1.finalize(), ha.finalize());
    }

    #[test]
    fn muhash_remove_set() {
        let mut h = MuHash3072::new();
        h.insert(b"aaa");
        h.insert(b"bbb");

        let mut h2 = MuHash3072::new();
        h2.insert(b"bbb");

        h.remove_set(&h2);

        let mut expected = MuHash3072::new();
        expected.insert(b"aaa");

        assert_eq!(h.finalize(), expected.finalize());
    }

    /// Bitcoin Core test vector:
    /// FromInt(0) * FromInt(1) / FromInt(2) should produce a known hash.
    ///
    /// FromInt(i) creates a MuHash from a 32-byte array where byte[0]=i, rest=0.
    #[test]
    fn muhash_bitcoin_core_test_vector() {
        fn from_int(i: u8) -> MuHash3072 {
            let mut data = [0u8; 32];
            data[0] = i;
            MuHash3072::from_data(&data)
        }

        // acc = FromInt(0); acc *= FromInt(1); acc /= FromInt(2);
        let mut acc = from_int(0);
        acc.combine(&from_int(1));
        acc.remove_set(&from_int(2));
        let out = acc.finalize();

        // Expected from Bitcoin Core test:
        // "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
        let expected = hex_to_hash256("10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863");
        assert_eq!(out, expected);
    }

    /// Same test but using insert/remove directly.
    #[test]
    fn muhash_bitcoin_core_test_vector_insert_remove() {
        fn from_int(i: u8) -> MuHash3072 {
            let mut data = [0u8; 32];
            data[0] = i;
            MuHash3072::from_data(&data)
        }

        let mut acc = from_int(0);
        let tmp = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        acc.insert(&tmp);
        let tmp2 = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        acc.remove(&tmp2);
        let out = acc.finalize();

        let expected = hex_to_hash256("10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863");
        assert_eq!(out, expected);
    }

    /// Test that x * y / (y * x) = identity.
    #[test]
    fn muhash_algebraic_identity() {
        fn from_int(i: u8) -> MuHash3072 {
            let mut data = [0u8; 32];
            data[0] = i;
            MuHash3072::from_data(&data)
        }

        let x = from_int(7);
        let y = from_int(13);

        let mut z = MuHash3072::new();
        z.combine(&x);  // z = X
        z.combine(&y);  // z = X*Y
        let mut yx = y.clone();
        yx.combine(&x); // yx = Y*X
        z.remove_set(&yx); // z = X*Y / (Y*X) = 1

        let empty = MuHash3072::new();
        assert_eq!(z.finalize(), empty.finalize());
    }

    /// Test the overflow case from Bitcoin Core.
    #[test]
    fn muhash_overflow() {
        // When the internal Num3072 value is all 0xFF bytes (= 2^3072 - 1),
        // which is larger than the modulus, it should still finalize correctly.
        // The expected hash for this case is from Bitcoin Core tests:
        // "3a31e6903aff0de9f62f9a9f7f8b861de76ce2cda09822b90014319ae5dc2271"
        let mut n = Num3072 { limbs: [u64::MAX; LIMBS] };
        // This represents 2^3072-1 which is >= modulus (2^3072 - 1103717).
        // Build a MuHash with this as numerator.
        let muhash = MuHash3072 {
            numerator: n.clone(),
            denominator: Num3072::one(),
        };
        let out = muhash.finalize();
        let expected = hex_to_hash256("7122dce59a311400b92298a0cde26ce71d868b7f9f9a2ff6e90dff3a90e6313a");
        assert_eq!(out, expected);
    }

    fn hex_to_hash256(hex: &str) -> Hash256 {
        let bytes = hex::decode(hex).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr.reverse(); // Bitcoin Core displays hashes in reversed byte order
        Hash256(arr)
    }
}
