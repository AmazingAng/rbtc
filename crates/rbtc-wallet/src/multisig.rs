//! Multisig redeemScript construction and P2SH multisig address generation.

use rbtc_crypto::hash160;
use rbtc_primitives::{network::Network, script::Script};

use crate::address::p2sh_address;

/// Create an M-of-N bare multisig redeemScript.
///
/// The resulting script has the form:
/// ```text
/// OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG
/// ```
///
/// # Panics
///
/// Panics if `m == 0`, `m > pubkeys.len()`, `pubkeys.is_empty()`, or
/// `pubkeys.len() > 16` (Bitcoin consensus limit for bare/P2SH multisig).
pub fn create_multisig_script(m: usize, pubkeys: &[&[u8]]) -> Script {
    let n = pubkeys.len();
    assert!(m >= 1, "threshold m must be >= 1");
    assert!(n >= 1, "must provide at least one public key");
    assert!(m <= n, "threshold m ({m}) must be <= n ({n})");
    assert!(n <= 16, "at most 16 keys allowed in multisig (got {n})");

    // Estimate capacity: OP_M(1) + N*(1+33 or 1+65) + OP_N(1) + OP_CHECKMULTISIG(1)
    let mut script = Vec::with_capacity(3 + n * 34);

    // OP_M: OP_1 = 0x51, OP_2 = 0x52, ... OP_16 = 0x60
    script.push(0x50 + m as u8);

    for pk in pubkeys {
        script.push(pk.len() as u8); // push length (33 for compressed, 65 for uncompressed)
        script.extend_from_slice(pk);
    }

    // OP_N
    script.push(0x50 + n as u8);

    // OP_CHECKMULTISIG
    script.push(0xae);

    Script::from_bytes(script)
}

/// Create an M-of-N P2SH multisig address.
///
/// Constructs the multisig redeemScript, hashes it with HASH160, and wraps it
/// in a P2SH address.
pub fn p2sh_multisig_address(m: usize, pubkeys: &[&[u8]], network: Network) -> String {
    let redeem_script = create_multisig_script(m, pubkeys);
    let script_hash = hash160(redeem_script.as_bytes());
    p2sh_address(&script_hash.0, network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::address_to_script;
    use crate::hd::ExtendedPrivKey;

    /// Helper: derive N distinct compressed public keys.
    fn sample_pubkeys(count: usize) -> Vec<Vec<u8>> {
        let seed = [1u8; 64];
        let master = ExtendedPrivKey::from_seed(&seed).unwrap();
        (0..count)
            .map(|i| {
                let child = master.derive_child(i as u32).unwrap();
                child.public_key().serialize().to_vec()
            })
            .collect()
    }

    #[test]
    fn create_1_of_2_multisig_script() {
        let pks = sample_pubkeys(2);
        let refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        let script = create_multisig_script(1, &refs);
        let bytes = script.as_bytes();

        // First byte: OP_1 (0x51)
        assert_eq!(bytes[0], 0x51);
        // Last byte: OP_CHECKMULTISIG (0xae)
        assert_eq!(*bytes.last().unwrap(), 0xae);
        // Second-to-last: OP_2 (0x52)
        assert_eq!(bytes[bytes.len() - 2], 0x52);
        // Total length: 1 + 2*(1+33) + 1 + 1 = 71
        assert_eq!(bytes.len(), 71);
    }

    #[test]
    fn create_2_of_3_multisig_script() {
        let pks = sample_pubkeys(3);
        let refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        let script = create_multisig_script(2, &refs);
        let bytes = script.as_bytes();

        assert_eq!(bytes[0], 0x52); // OP_2
        assert_eq!(bytes[bytes.len() - 2], 0x53); // OP_3
        assert_eq!(*bytes.last().unwrap(), 0xae);
        // 1 + 3*(1+33) + 1 + 1 = 105
        assert_eq!(bytes.len(), 105);
    }

    #[test]
    #[should_panic(expected = "threshold m must be >= 1")]
    fn create_multisig_zero_m_panics() {
        let pks = sample_pubkeys(1);
        let refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        create_multisig_script(0, &refs);
    }

    #[test]
    #[should_panic(expected = "threshold m (3) must be <= n (2)")]
    fn create_multisig_m_exceeds_n_panics() {
        let pks = sample_pubkeys(2);
        let refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        create_multisig_script(3, &refs);
    }

    #[test]
    fn p2sh_multisig_address_mainnet_2_of_3() {
        let pks = sample_pubkeys(3);
        let refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        let addr = p2sh_multisig_address(2, &refs, Network::Mainnet);
        assert!(
            addr.starts_with('3'),
            "mainnet P2SH multisig should start with '3', got {addr}"
        );
        // Verify the address decodes to a P2SH scriptPubKey
        let spk = address_to_script(&addr).unwrap();
        assert!(spk.is_p2sh());
    }

    #[test]
    fn p2sh_multisig_address_testnet_1_of_2() {
        let pks = sample_pubkeys(2);
        let refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        let addr = p2sh_multisig_address(1, &refs, Network::Testnet4);
        assert!(
            addr.starts_with('2'),
            "testnet P2SH multisig should start with '2', got {addr}"
        );
    }

    #[test]
    fn p2sh_multisig_address_regtest() {
        let pks = sample_pubkeys(2);
        let refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        let addr = p2sh_multisig_address(1, &refs, Network::Regtest);
        assert!(
            addr.starts_with('2'),
            "regtest P2SH multisig should start with '2', got {addr}"
        );
    }

    #[test]
    fn different_key_orders_produce_different_addresses() {
        let pks = sample_pubkeys(3);
        let refs_a: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        let refs_b: Vec<&[u8]> = vec![pks[2].as_slice(), pks[0].as_slice(), pks[1].as_slice()];
        let addr_a = p2sh_multisig_address(2, &refs_a, Network::Mainnet);
        let addr_b = p2sh_multisig_address(2, &refs_b, Network::Mainnet);
        // Different key ordering should produce different redeemScripts and thus different addresses
        assert_ne!(addr_a, addr_b);
    }

    #[test]
    fn p2sh_multisig_1_of_1() {
        let pks = sample_pubkeys(1);
        let refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        let addr = p2sh_multisig_address(1, &refs, Network::Mainnet);
        assert!(addr.starts_with('3'));
    }
}
