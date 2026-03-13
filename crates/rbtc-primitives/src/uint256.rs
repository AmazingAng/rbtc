/// Minimal 256-bit unsigned integer for chainwork arithmetic.
///
/// Matches Bitcoin Core's `arith_uint256` for the operations we need:
/// addition, comparison, conversion to/from LE bytes, hex display.

/// A 256-bit unsigned integer stored as 4 little-endian u64 limbs.
/// limbs[0] is the least significant.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = U256([0; 4]);
    pub const MAX: Self = U256([u64::MAX; 4]);

    /// Create from a u64 value.
    pub const fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }

    /// Create from a u128 value (for migration from existing code).
    pub const fn from_u128(v: u128) -> Self {
        U256([v as u64, (v >> 64) as u64, 0, 0])
    }

    /// Convert to u128 (lossy: drops high 128 bits).
    pub const fn low_u128(&self) -> u128 {
        (self.0[0] as u128) | ((self.0[1] as u128) << 64)
    }

    /// Returns true if the value is zero.
    pub const fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Saturating addition.
    pub fn saturating_add(self, rhs: Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            result[i] = sum;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry > 0 {
            Self::MAX
        } else {
            U256(result)
        }
    }

    /// Division: self / rhs. Returns ZERO if rhs is zero.
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        if rhs.is_zero() {
            return None;
        }
        // Simple long division for our use case (computing work from target).
        // For the chainwork computation we divide MAX by a small-ish target,
        // so this doesn't need to be fast.
        let mut quotient = U256::ZERO;
        let mut remainder = U256::ZERO;
        for bit in (0..256).rev() {
            // remainder <<= 1
            remainder = remainder.shl1();
            // remainder |= bit `bit` of self
            let limb = bit / 64;
            let pos = bit % 64;
            if (self.0[limb] >> pos) & 1 == 1 {
                remainder.0[0] |= 1;
            }
            if remainder >= rhs {
                remainder = remainder.sub_no_underflow(rhs);
                let q_limb = bit / 64;
                let q_pos = bit % 64;
                quotient.0[q_limb] |= 1u64 << q_pos;
            }
        }
        Some(quotient)
    }

    /// Shift left by 1 bit.
    fn shl1(self) -> Self {
        let mut r = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            r[i] = (self.0[i] << 1) | carry;
            carry = self.0[i] >> 63;
        }
        U256(r)
    }

    /// Subtract without underflow check (caller must ensure self >= rhs).
    fn sub_no_underflow(self, rhs: Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (diff, b2) = diff.overflowing_sub(borrow);
            result[i] = diff;
            borrow = (b1 as u64) + (b2 as u64);
        }
        U256(result)
    }

    /// Encode as 32 bytes, little-endian.
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&self.0[i].to_le_bytes());
        }
        bytes
    }

    /// Decode from 32 bytes, little-endian.
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        U256(limbs)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare from most significant limb down
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl std::fmt::Debug for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "U256({})", self)
    }
}

impl std::fmt::Display for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as 64-char zero-padded hex (big-endian)
        write!(
            f,
            "{:016x}{:016x}{:016x}{:016x}",
            self.0[3], self.0[2], self.0[1], self.0[0]
        )
    }
}

impl std::fmt::LowerHex for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        if let Some(width) = f.width() {
            // zero-padded formatting
            write!(
                f,
                "{:0>width$}",
                format!(
                    "{:016x}{:016x}{:016x}{:016x}",
                    self.0[3], self.0[2], self.0[1], self.0[0]
                ),
                width = width,
            )
        } else {
            write!(
                f,
                "{:016x}{:016x}{:016x}{:016x}",
                self.0[3], self.0[2], self.0[1], self.0[0]
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_max() {
        assert!(U256::ZERO.is_zero());
        assert!(!U256::MAX.is_zero());
        assert!(U256::ZERO < U256::MAX);
    }

    #[test]
    fn from_u64_and_u128() {
        let a = U256::from_u64(42);
        assert_eq!(a.0, [42, 0, 0, 0]);

        let b = U256::from_u128(u128::MAX);
        assert_eq!(b.0, [u64::MAX, u64::MAX, 0, 0]);
        assert_eq!(b.low_u128(), u128::MAX);
    }

    #[test]
    fn saturating_add_basic() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        let c = a.saturating_add(b);
        assert_eq!(c.0[0], 300);
        assert_eq!(c.0[1], 0);
    }

    #[test]
    fn saturating_add_overflow() {
        let result = U256::MAX.saturating_add(U256::from_u64(1));
        assert_eq!(result, U256::MAX);
    }

    #[test]
    fn saturating_add_carry() {
        let a = U256([u64::MAX, 0, 0, 0]);
        let b = U256::from_u64(1);
        let c = a.saturating_add(b);
        assert_eq!(c.0, [0, 1, 0, 0]);
    }

    #[test]
    fn ordering() {
        let a = U256::from_u64(10);
        let b = U256::from_u64(20);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, a);

        let high = U256([0, 0, 0, 1]);
        assert!(high > U256::from_u128(u128::MAX));
    }

    #[test]
    fn le_bytes_roundtrip() {
        let a = U256([0x1122334455667788, 0xAABBCCDDEEFF0011, 0x0102030405060708, 0xF0E0D0C0B0A09080]);
        let bytes = a.to_le_bytes();
        let b = U256::from_le_bytes(bytes);
        assert_eq!(a, b);
    }

    #[test]
    fn hex_display() {
        let a = U256::from_u64(0xFF);
        let s = format!("{:064x}", a);
        assert_eq!(s.len(), 64);
        assert!(s.ends_with("00000000000000ff"));
    }

    #[test]
    fn checked_div_basic() {
        let max = U256::MAX;
        let one = U256::from_u64(1);
        assert_eq!(max.checked_div(one), Some(max));

        let two = U256::from_u64(2);
        let result = U256::from_u64(100).checked_div(two).unwrap();
        assert_eq!(result, U256::from_u64(50));
    }

    #[test]
    fn checked_div_by_zero() {
        assert_eq!(U256::from_u64(1).checked_div(U256::ZERO), None);
    }
}
