/// Bitcoin script opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // Constants
    Op0 = 0x00,
    OpPushData1 = 0x4c,
    OpPushData2 = 0x4d,
    OpPushData4 = 0x4e,
    Op1Negate = 0x4f,
    OpReserved = 0x50,
    Op1 = 0x51,
    Op2 = 0x52,
    Op3 = 0x53,
    Op4 = 0x54,
    Op5 = 0x55,
    Op6 = 0x56,
    Op7 = 0x57,
    Op8 = 0x58,
    Op9 = 0x59,
    Op10 = 0x5a,
    Op11 = 0x5b,
    Op12 = 0x5c,
    Op13 = 0x5d,
    Op14 = 0x5e,
    Op15 = 0x5f,
    Op16 = 0x60,

    // Flow control
    OpNop = 0x61,
    OpVer = 0x62,
    OpIf = 0x63,
    OpNotIf = 0x64,
    OpVerIf = 0x65,
    OpVerNotIf = 0x66,
    OpElse = 0x67,
    OpEndIf = 0x68,
    OpVerify = 0x69,
    OpReturn = 0x6a,

    // Stack
    OpToAltStack = 0x6b,
    OpFromAltStack = 0x6c,
    OpIfDup = 0x73,
    OpDepth = 0x74,
    OpDrop = 0x75,
    OpDup = 0x76,
    OpNip = 0x77,
    OpOver = 0x78,
    OpPick = 0x79,
    OpRoll = 0x7a,
    OpRot = 0x7b,
    OpSwap = 0x7c,
    OpTuck = 0x7d,
    Op2Drop = 0x6d,
    Op2Dup = 0x6e,
    Op3Dup = 0x6f,
    Op2Over = 0x70,
    Op2Rot = 0x71,
    Op2Swap = 0x72,

    // Splice
    OpCat = 0x7e,    // disabled
    OpSubStr = 0x7f, // disabled
    OpLeft = 0x80,   // disabled
    OpRight = 0x81,  // disabled
    OpSize = 0x82,

    // Bitwise logic
    OpInvert = 0x83, // disabled
    OpAnd = 0x84,    // disabled
    OpOr = 0x85,     // disabled
    OpXor = 0x86,    // disabled
    OpEqual = 0x87,
    OpEqualVerify = 0x88,
    OpReserved1 = 0x89,
    OpReserved2 = 0x8a,

    // Arithmetic
    Op1Add = 0x8b,
    Op1Sub = 0x8c,
    Op2Mul = 0x8d,    // disabled
    Op2Div = 0x8e,    // disabled
    OpNegate = 0x8f,
    OpAbs = 0x90,
    OpNot = 0x91,
    Op0NotEqual = 0x92,
    OpAdd = 0x93,
    OpSub = 0x94,
    OpMul = 0x95,     // disabled
    OpDiv = 0x96,     // disabled
    OpMod = 0x97,     // disabled
    OpLShift = 0x98,  // disabled
    OpRShift = 0x99,  // disabled
    OpBoolAnd = 0x9a,
    OpBoolOr = 0x9b,
    OpNumEqual = 0x9c,
    OpNumEqualVerify = 0x9d,
    OpNumNotEqual = 0x9e,
    OpLessThan = 0x9f,
    OpGreaterThan = 0xa0,
    OpLessThanOrEqual = 0xa1,
    OpGreaterThanOrEqual = 0xa2,
    OpMin = 0xa3,
    OpMax = 0xa4,
    OpWithin = 0xa5,

    // Crypto
    OpRipemd160 = 0xa6,
    OpSha1 = 0xa7,
    OpSha256 = 0xa8,
    OpHash160 = 0xa9,
    OpHash256 = 0xaa,
    OpCodeSeparator = 0xab,
    OpCheckSig = 0xac,
    OpCheckSigVerify = 0xad,
    OpCheckMultiSig = 0xae,
    OpCheckMultiSigVerify = 0xaf,

    // Locktime (BIP65, BIP112)
    OpNop1 = 0xb0,
    OpCheckLockTimeVerify = 0xb1,
    OpCheckSequenceVerify = 0xb2,
    OpNop4 = 0xb3,
    OpNop5 = 0xb4,
    OpNop6 = 0xb5,
    OpNop7 = 0xb6,
    OpNop8 = 0xb7,
    OpNop9 = 0xb8,
    OpNop10 = 0xb9,

    // Tapscript (BIP342)
    OpCheckSigAdd = 0xba,

    OpInvalidOpcode = 0xff,
}

impl Opcode {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::Op0,
            0x4c => Self::OpPushData1,
            0x4d => Self::OpPushData2,
            0x4e => Self::OpPushData4,
            0x4f => Self::Op1Negate,
            0x50 => Self::OpReserved,
            0x51 => Self::Op1,
            0x52 => Self::Op2,
            0x53 => Self::Op3,
            0x54 => Self::Op4,
            0x55 => Self::Op5,
            0x56 => Self::Op6,
            0x57 => Self::Op7,
            0x58 => Self::Op8,
            0x59 => Self::Op9,
            0x5a => Self::Op10,
            0x5b => Self::Op11,
            0x5c => Self::Op12,
            0x5d => Self::Op13,
            0x5e => Self::Op14,
            0x5f => Self::Op15,
            0x60 => Self::Op16,
            0x61 => Self::OpNop,
            0x62 => Self::OpVer,
            0x63 => Self::OpIf,
            0x64 => Self::OpNotIf,
            0x65 => Self::OpVerIf,
            0x66 => Self::OpVerNotIf,
            0x67 => Self::OpElse,
            0x68 => Self::OpEndIf,
            0x69 => Self::OpVerify,
            0x6a => Self::OpReturn,
            0x6b => Self::OpToAltStack,
            0x6c => Self::OpFromAltStack,
            0x6d => Self::Op2Drop,
            0x6e => Self::Op2Dup,
            0x6f => Self::Op3Dup,
            0x70 => Self::Op2Over,
            0x71 => Self::Op2Rot,
            0x72 => Self::Op2Swap,
            0x73 => Self::OpIfDup,
            0x74 => Self::OpDepth,
            0x75 => Self::OpDrop,
            0x76 => Self::OpDup,
            0x77 => Self::OpNip,
            0x78 => Self::OpOver,
            0x79 => Self::OpPick,
            0x7a => Self::OpRoll,
            0x7b => Self::OpRot,
            0x7c => Self::OpSwap,
            0x7d => Self::OpTuck,
            0x82 => Self::OpSize,
            0x87 => Self::OpEqual,
            0x88 => Self::OpEqualVerify,
            0x8b => Self::Op1Add,
            0x8c => Self::Op1Sub,
            0x8f => Self::OpNegate,
            0x90 => Self::OpAbs,
            0x91 => Self::OpNot,
            0x92 => Self::Op0NotEqual,
            0x93 => Self::OpAdd,
            0x94 => Self::OpSub,
            0x9a => Self::OpBoolAnd,
            0x9b => Self::OpBoolOr,
            0x9c => Self::OpNumEqual,
            0x9d => Self::OpNumEqualVerify,
            0x9e => Self::OpNumNotEqual,
            0x9f => Self::OpLessThan,
            0xa0 => Self::OpGreaterThan,
            0xa1 => Self::OpLessThanOrEqual,
            0xa2 => Self::OpGreaterThanOrEqual,
            0xa3 => Self::OpMin,
            0xa4 => Self::OpMax,
            0xa5 => Self::OpWithin,
            0xa6 => Self::OpRipemd160,
            0xa7 => Self::OpSha1,
            0xa8 => Self::OpSha256,
            0xa9 => Self::OpHash160,
            0xaa => Self::OpHash256,
            0xab => Self::OpCodeSeparator,
            0xac => Self::OpCheckSig,
            0xad => Self::OpCheckSigVerify,
            0xae => Self::OpCheckMultiSig,
            0xaf => Self::OpCheckMultiSigVerify,
            0xb0 => Self::OpNop1,
            0xb1 => Self::OpCheckLockTimeVerify,
            0xb2 => Self::OpCheckSequenceVerify,
            0xb3 => Self::OpNop4,
            0xb4 => Self::OpNop5,
            0xb5 => Self::OpNop6,
            0xb6 => Self::OpNop7,
            0xb7 => Self::OpNop8,
            0xb8 => Self::OpNop9,
            0xb9 => Self::OpNop10,
            0xba => Self::OpCheckSigAdd,
            _ => Self::OpInvalidOpcode,
        }
    }

    pub fn is_disabled(&self) -> bool {
        matches!(
            self,
            Self::OpCat
                | Self::OpSubStr
                | Self::OpLeft
                | Self::OpRight
                | Self::OpInvert
                | Self::OpAnd
                | Self::OpOr
                | Self::OpXor
                | Self::Op2Mul
                | Self::Op2Div
                | Self::OpMul
                | Self::OpDiv
                | Self::OpMod
                | Self::OpLShift
                | Self::OpRShift
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_byte_constants() {
        assert_eq!(Opcode::from_byte(0x00), Opcode::Op0);
        assert_eq!(Opcode::from_byte(0x51), Opcode::Op1);
        assert_eq!(Opcode::from_byte(0x60), Opcode::Op16);
    }

    #[test]
    fn from_byte_flow_and_stack() {
        assert_eq!(Opcode::from_byte(0x63), Opcode::OpIf);
        assert_eq!(Opcode::from_byte(0x67), Opcode::OpElse);
        assert_eq!(Opcode::from_byte(0x68), Opcode::OpEndIf);
        assert_eq!(Opcode::from_byte(0x76), Opcode::OpDup);
        assert_eq!(Opcode::from_byte(0x6a), Opcode::OpReturn);
    }

    #[test]
    fn from_byte_crypto() {
        assert_eq!(Opcode::from_byte(0xa9), Opcode::OpHash160);
        assert_eq!(Opcode::from_byte(0xac), Opcode::OpCheckSig);
    }

    #[test]
    fn from_byte_invalid() {
        assert_eq!(Opcode::from_byte(0xfe), Opcode::OpInvalidOpcode);
    }

    #[test]
    fn is_disabled() {
        assert!(Opcode::OpCat.is_disabled());
        assert!(Opcode::OpAnd.is_disabled());
        assert!(!Opcode::OpDup.is_disabled());
    }
}
