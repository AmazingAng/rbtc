//! Block validation status flags, matching Bitcoin Core's `BlockStatus`.
//!
//! The status is stored as a `u32` internally but serialised to a single `u8`
//! on disk for backward compatibility with existing block-index records.

/// Validation level constants (occupy the low 3 bits).
pub const BLOCK_VALID_UNKNOWN: u32 = 0;
pub const BLOCK_VALID_RESERVED: u32 = 1;
pub const BLOCK_VALID_TREE: u32 = 2;
pub const BLOCK_VALID_TRANSACTIONS: u32 = 3;
pub const BLOCK_VALID_CHAIN: u32 = 4;
pub const BLOCK_VALID_SCRIPTS: u32 = 5;
pub const BLOCK_VALID_MASK: u32 = 0x07;

/// Data-availability flags.
pub const BLOCK_HAVE_DATA: u32 = 8;
pub const BLOCK_HAVE_UNDO: u32 = 16;
pub const BLOCK_HAVE_MASK: u32 = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;

/// Failure flags.
pub const BLOCK_FAILED_VALID: u32 = 32;
pub const BLOCK_FAILED_CHILD: u32 = 64;
pub const BLOCK_FAILED_MASK: u32 = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD;

/// Witness flag.
pub const BLOCK_OPT_WITNESS: u32 = 128;

/// Block status flags mirroring Bitcoin Core's `BlockStatus`.
///
/// Internally wraps a `u32`; the low 3 bits encode the highest reached
/// validation level, while the remaining bits are independent flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockStatus(u32);

impl BlockStatus {
    /// Create a new status with all flags cleared (`BLOCK_VALID_UNKNOWN`).
    pub fn new() -> Self {
        Self(0)
    }

    /// Construct from a raw `u32` value.
    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw `u32` representation.
    pub fn raw(&self) -> u32 {
        self.0
    }

    // -- query methods -------------------------------------------------------

    /// Return the validation level (low 3 bits).
    pub fn validity(&self) -> u32 {
        self.0 & BLOCK_VALID_MASK
    }

    /// `true` if the block has reached at least `level` **and** has not failed.
    pub fn is_valid(&self, level: u32) -> bool {
        self.validity() >= level && !self.has_failed()
    }

    /// `true` if `BLOCK_HAVE_DATA` is set.
    pub fn have_data(&self) -> bool {
        self.0 & BLOCK_HAVE_DATA != 0
    }

    /// `true` if `BLOCK_HAVE_UNDO` is set.
    pub fn have_undo(&self) -> bool {
        self.0 & BLOCK_HAVE_UNDO != 0
    }

    /// `true` if either `BLOCK_FAILED_VALID` or `BLOCK_FAILED_CHILD` is set.
    pub fn has_failed(&self) -> bool {
        self.0 & BLOCK_FAILED_MASK != 0
    }

    /// `true` if `BLOCK_FAILED_CHILD` is set (descends from a failed block).
    pub fn has_failed_parent(&self) -> bool {
        self.0 & BLOCK_FAILED_CHILD != 0
    }

    /// `true` if `BLOCK_OPT_WITNESS` is set.
    pub fn has_opt_witness(&self) -> bool {
        self.0 & BLOCK_OPT_WITNESS != 0
    }

    // -- builder methods (return a new value) --------------------------------

    /// Raise the validation level to `level` if it is higher than the current
    /// level.  Other flags are preserved.
    pub fn with_validity(self, level: u32) -> Self {
        let current = self.validity();
        if level > current {
            Self((self.0 & !BLOCK_VALID_MASK) | (level & BLOCK_VALID_MASK))
        } else {
            self
        }
    }

    /// Set the `BLOCK_HAVE_DATA` flag.
    pub fn with_data(self) -> Self {
        Self(self.0 | BLOCK_HAVE_DATA)
    }

    /// Set the `BLOCK_HAVE_UNDO` flag.
    pub fn with_undo(self) -> Self {
        Self(self.0 | BLOCK_HAVE_UNDO)
    }

    /// Set the `BLOCK_FAILED_VALID` flag.
    pub fn with_failed(self) -> Self {
        Self(self.0 | BLOCK_FAILED_VALID)
    }

    /// Set the `BLOCK_FAILED_CHILD` flag.
    pub fn with_failed_child(self) -> Self {
        Self(self.0 | BLOCK_FAILED_CHILD)
    }

    /// Clear both `BLOCK_FAILED_VALID` and `BLOCK_FAILED_CHILD` flags.
    pub fn without_failed(self) -> Self {
        Self(self.0 & !BLOCK_FAILED_MASK)
    }

    /// Set the `BLOCK_OPT_WITNESS` flag.
    pub fn with_opt_witness(self) -> Self {
        Self(self.0 | BLOCK_OPT_WITNESS)
    }

    // -- serialisation helpers (backward-compatible u8) -----------------------

    /// Encode to a single byte for on-disk storage (truncates to low 8 bits).
    pub fn to_u8(self) -> u8 {
        self.0 as u8
    }

    /// Decode from a single on-disk byte.
    pub fn from_u8(b: u8) -> Self {
        Self(b as u32)
    }
}

impl Default for BlockStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for BlockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockStatus(0x{:04x})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_status_is_unknown() {
        let s = BlockStatus::new();
        assert_eq!(s.raw(), 0);
        assert_eq!(s.validity(), BLOCK_VALID_UNKNOWN);
        assert!(!s.have_data());
        assert!(!s.have_undo());
        assert!(!s.has_failed());
        assert!(!s.has_opt_witness());
    }

    #[test]
    fn validity_levels_ordered() {
        let s = BlockStatus::new()
            .with_validity(BLOCK_VALID_TREE);
        assert_eq!(s.validity(), BLOCK_VALID_TREE);
        assert!(s.is_valid(BLOCK_VALID_TREE));
        assert!(s.is_valid(BLOCK_VALID_RESERVED));
        assert!(!s.is_valid(BLOCK_VALID_TRANSACTIONS));

        // Raising validity works
        let s2 = s.with_validity(BLOCK_VALID_SCRIPTS);
        assert_eq!(s2.validity(), BLOCK_VALID_SCRIPTS);

        // Lowering validity is a no-op
        let s3 = s2.with_validity(BLOCK_VALID_TREE);
        assert_eq!(s3.validity(), BLOCK_VALID_SCRIPTS);
    }

    #[test]
    fn have_data_and_undo() {
        let s = BlockStatus::new()
            .with_validity(BLOCK_VALID_TRANSACTIONS)
            .with_data()
            .with_undo();
        assert!(s.have_data());
        assert!(s.have_undo());
        assert_eq!(s.raw() & BLOCK_HAVE_MASK, BLOCK_HAVE_MASK);
        // Validity is preserved
        assert_eq!(s.validity(), BLOCK_VALID_TRANSACTIONS);
    }

    #[test]
    fn failed_blocks() {
        let s = BlockStatus::new()
            .with_validity(BLOCK_VALID_TREE)
            .with_failed();
        assert!(s.has_failed());
        assert!(!s.has_failed_parent());

        let s2 = BlockStatus::new().with_failed_child();
        assert!(s2.has_failed());
        assert!(s2.has_failed_parent());
    }

    #[test]
    fn is_valid_rejects_failed() {
        let s = BlockStatus::new()
            .with_validity(BLOCK_VALID_SCRIPTS)
            .with_failed();
        // Even though validity is at SCRIPTS level, is_valid returns false
        assert!(!s.is_valid(BLOCK_VALID_UNKNOWN));
        assert_eq!(s.validity(), BLOCK_VALID_SCRIPTS);
    }

    #[test]
    fn without_failed_clears_both_flags() {
        let s = BlockStatus::new()
            .with_validity(BLOCK_VALID_SCRIPTS)
            .with_data()
            .with_failed()
            .with_failed_child();
        assert!(s.has_failed());

        let s2 = s.without_failed();
        assert!(!s2.has_failed());
        assert!(!s2.has_failed_parent());
        // Other flags preserved
        assert_eq!(s2.validity(), BLOCK_VALID_SCRIPTS);
        assert!(s2.have_data());
    }

    #[test]
    fn with_opt_witness() {
        let s = BlockStatus::new()
            .with_data()
            .with_opt_witness();
        assert!(s.has_opt_witness());
        assert!(s.have_data());
        assert_eq!(s.raw(), BLOCK_HAVE_DATA | BLOCK_OPT_WITNESS);
    }

    #[test]
    fn u8_roundtrip() {
        let s = BlockStatus::new()
            .with_validity(BLOCK_VALID_TRANSACTIONS)
            .with_data()
            .with_opt_witness();
        let byte = s.to_u8();
        let s2 = BlockStatus::from_u8(byte);
        assert_eq!(s.raw(), s2.raw());
    }

    #[test]
    fn from_raw_roundtrip() {
        let raw = BLOCK_VALID_CHAIN | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO | BLOCK_OPT_WITNESS;
        let s = BlockStatus::from_raw(raw);
        assert_eq!(s.raw(), raw);
        assert_eq!(s.validity(), BLOCK_VALID_CHAIN);
        assert!(s.have_data());
        assert!(s.have_undo());
        assert!(s.has_opt_witness());
    }
}
