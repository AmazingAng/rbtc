//! External signer framework for hardware wallet integration.
//!
//! Matches Bitcoin Core's external signer interface (`-signer=<cmd>`),
//! which communicates with HWI-compatible tools via JSON over stdin/stdout.
//!
//! # Protocol
//!
//! The external process supports these subcommands:
//! - `enumerate` — lists connected devices as a JSON array
//! - `getdescriptors --account <n>` — returns receive/change descriptors
//! - `displayaddress --desc <descriptor>` — shows address on device
//! - `signtx <base64-psbt>` (via stdin with `--stdin`) — signs a PSBT

use crate::error::WalletError;
use rbtc_psbt::Psbt;

/// Network identifier for the signer protocol (matches Bitcoin Core).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerChain {
    Main,
    Test,
    Regtest,
    Signet,
}

impl SignerChain {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignerChain::Main => "main",
            SignerChain::Test => "test",
            SignerChain::Regtest => "regtest",
            SignerChain::Signet => "signet",
        }
    }
}

/// Device info returned by the `enumerate` command.
#[derive(Debug, Clone)]
pub struct SignerDevice {
    /// Master key fingerprint (hex, 8 chars).
    pub fingerprint: String,
    /// Device model name (e.g. "trezor_1", "ledger_nano_s").
    pub model: String,
}

/// Result of a `getdescriptors` call.
#[derive(Debug, Clone)]
pub struct SignerDescriptors {
    /// Receive descriptor(s).
    pub receive: Vec<String>,
    /// Change/internal descriptor(s).
    pub change: Vec<String>,
}

/// Trait for external signing devices.
///
/// This abstracts the interaction with a hardware wallet or any external
/// signer that follows the HWI JSON protocol used by Bitcoin Core.
pub trait ExternalSigner {
    /// Enumerate connected devices.
    fn enumerate(&self) -> Result<Vec<SignerDevice>, WalletError>;

    /// Get receive and change descriptors for the given BIP32 account.
    fn get_descriptors(
        &self,
        fingerprint: &str,
        account: u32,
    ) -> Result<SignerDescriptors, WalletError>;

    /// Display an address on the device for verification.
    fn display_address(
        &self,
        fingerprint: &str,
        descriptor: &str,
    ) -> Result<(), WalletError>;

    /// Sign a PSBT using the external device.
    ///
    /// The signer should only sign inputs whose BIP32 derivation
    /// fingerprint matches the device's master fingerprint.
    /// Returns the updated PSBT with signatures added.
    fn sign_psbt(
        &self,
        fingerprint: &str,
        psbt: &Psbt,
    ) -> Result<Psbt, WalletError>;
}

/// Process-based external signer that delegates to an HWI-compatible binary.
///
/// Equivalent to Bitcoin Core's `ExternalSigner` class which invokes the
/// command specified by `-signer=<path>`.
#[derive(Debug, Clone)]
pub struct ProcessExternalSigner {
    /// Path to the signer binary (e.g. "hwi" or "/usr/bin/hwi").
    command: String,
    /// Network to operate on.
    chain: SignerChain,
}

impl ProcessExternalSigner {
    pub fn new(command: String, chain: SignerChain) -> Self {
        Self { command, chain }
    }

    /// Build command arguments with network flags.
    fn network_args(&self) -> Vec<String> {
        vec!["--chain".to_string(), self.chain.as_str().to_string()]
    }

    /// Run the external process with the given arguments and optional stdin,
    /// returning the parsed JSON output.
    fn run_command(
        &self,
        args: &[String],
        stdin_data: Option<&str>,
    ) -> Result<serde_json::Value, WalletError> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut cmd = Command::new(&self.command);
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        }

        let mut child = cmd.spawn().map_err(|e| {
            WalletError::SignerProcess(format!(
                "failed to spawn '{}': {}",
                self.command, e
            ))
        })?;

        if let Some(data) = stdin_data {
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(data.as_bytes()).map_err(|e| {
                    WalletError::SignerProcess(format!("failed to write stdin: {}", e))
                })?;
            }
            // Drop stdin so the child sees EOF.
            drop(child.stdin.take());
        }

        let output = child.wait_with_output().map_err(|e| {
            WalletError::SignerProcess(format!("process wait failed: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WalletError::SignerProcess(format!(
                "process exited with {}: {}",
                output.status,
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(stdout.trim()).map_err(|e| {
            WalletError::ExternalSigner(format!("invalid JSON from signer: {}", e))
        })
    }
}

impl ExternalSigner for ProcessExternalSigner {
    fn enumerate(&self) -> Result<Vec<SignerDevice>, WalletError> {
        let result = self.run_command(&["enumerate".to_string()], None)?;

        let arr = result.as_array().ok_or_else(|| {
            WalletError::ExternalSigner(
                "enumerate: expected JSON array".to_string(),
            )
        })?;

        let mut devices = Vec::new();
        let mut seen_fingerprints = std::collections::HashSet::new();

        for entry in arr {
            // Check for error field
            if let Some(err) = entry.get("error").and_then(|v| v.as_str()) {
                return Err(WalletError::ExternalSigner(format!(
                    "device error: {}",
                    err
                )));
            }

            let fingerprint = entry
                .get("fingerprint")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    WalletError::ExternalSigner(
                        "enumerate: missing fingerprint".to_string(),
                    )
                })?
                .to_string();

            // Skip duplicates (matching Bitcoin Core behavior)
            if !seen_fingerprints.insert(fingerprint.clone()) {
                continue;
            }

            let model = entry
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            devices.push(SignerDevice {
                fingerprint,
                model,
            });
        }

        Ok(devices)
    }

    fn get_descriptors(
        &self,
        fingerprint: &str,
        account: u32,
    ) -> Result<SignerDescriptors, WalletError> {
        let mut args = vec![
            "--fingerprint".to_string(),
            fingerprint.to_string(),
        ];
        args.extend(self.network_args());
        args.push("getdescriptors".to_string());
        args.push("--account".to_string());
        args.push(account.to_string());

        let result = self.run_command(&args, None)?;

        let receive = result
            .get("receive")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let change = result
            .get("internal")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(SignerDescriptors { receive, change })
    }

    fn display_address(
        &self,
        fingerprint: &str,
        descriptor: &str,
    ) -> Result<(), WalletError> {
        let mut args = vec![
            "--fingerprint".to_string(),
            fingerprint.to_string(),
        ];
        args.extend(self.network_args());
        args.push("displayaddress".to_string());
        args.push("--desc".to_string());
        args.push(descriptor.to_string());

        let result = self.run_command(&args, None)?;

        if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
            return Err(WalletError::ExternalSigner(format!(
                "displayaddress error: {}",
                err
            )));
        }

        Ok(())
    }

    fn sign_psbt(
        &self,
        fingerprint: &str,
        psbt: &Psbt,
    ) -> Result<Psbt, WalletError> {
        // Check that at least one input has a BIP32 derivation matching
        // the signer fingerprint (matching Bitcoin Core's check).
        let fp_bytes = hex::decode(fingerprint).map_err(|e| {
            WalletError::ExternalSigner(format!("invalid fingerprint hex: {}", e))
        })?;

        let has_matching_input = psbt.inputs.iter().any(|input| {
            // Check legacy BIP32 derivation paths
            let legacy_match = input
                .bip32_derivation
                .values()
                .any(|(fp, _)| *fp == fp_bytes);
            // Check taproot BIP32 derivation paths
            let tap_match = input
                .tap_bip32_derivation
                .values()
                .any(|(_, fp, _)| *fp == fp_bytes);
            legacy_match || tap_match
        });

        if !has_matching_input {
            return Err(WalletError::SignerFingerprintMismatch {
                signer: fingerprint.to_string(),
            });
        }

        let psbt_base64 = psbt.to_base64();

        let mut args = vec![
            "--stdin".to_string(),
            "--fingerprint".to_string(),
            fingerprint.to_string(),
        ];
        args.extend(self.network_args());

        let stdin_data = format!("signtx {}", psbt_base64);
        let result = self.run_command(&args, Some(&stdin_data))?;

        if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
            return Err(WalletError::ExternalSigner(format!(
                "signtx error: {}",
                err
            )));
        }

        let signed_b64 = result
            .get("psbt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                WalletError::ExternalSigner(
                    "signtx: missing 'psbt' field in response".to_string(),
                )
            })?;

        Psbt::from_base64(signed_b64).map_err(|e| {
            WalletError::ExternalSigner(format!("failed to decode signed PSBT: {}", e))
        })
    }
}

/// A mock external signer for testing. Implements the `ExternalSigner` trait
/// with configurable responses.
#[cfg(test)]
pub(crate) struct MockExternalSigner {
    pub devices: Vec<SignerDevice>,
    pub descriptors: SignerDescriptors,
    /// If set, `sign_psbt` returns this PSBT (simulating the device adding signatures).
    pub sign_result: Option<Psbt>,
    /// If set, `sign_psbt` returns this error.
    pub sign_error: Option<String>,
}

#[cfg(test)]
impl ExternalSigner for MockExternalSigner {
    fn enumerate(&self) -> Result<Vec<SignerDevice>, WalletError> {
        Ok(self.devices.clone())
    }

    fn get_descriptors(
        &self,
        _fingerprint: &str,
        _account: u32,
    ) -> Result<SignerDescriptors, WalletError> {
        Ok(self.descriptors.clone())
    }

    fn display_address(
        &self,
        _fingerprint: &str,
        _descriptor: &str,
    ) -> Result<(), WalletError> {
        Ok(())
    }

    fn sign_psbt(
        &self,
        fingerprint: &str,
        psbt: &Psbt,
    ) -> Result<Psbt, WalletError> {
        if let Some(ref err) = self.sign_error {
            return Err(WalletError::ExternalSigner(err.clone()));
        }

        // Check fingerprint match (same logic as ProcessExternalSigner)
        let fp_bytes = hex::decode(fingerprint).unwrap_or_default();
        let has_matching_input = psbt.inputs.iter().any(|input| {
            input
                .bip32_derivation
                .values()
                .any(|(fp, _)| *fp == fp_bytes)
                || input
                    .tap_bip32_derivation
                    .values()
                    .any(|(_, fp, _)| *fp == fp_bytes)
        });

        if !has_matching_input {
            return Err(WalletError::SignerFingerprintMismatch {
                signer: fingerprint.to_string(),
            });
        }

        Ok(self.sign_result.clone().unwrap_or_else(|| psbt.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbtc_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use rbtc_primitives::script::Script;
    use rbtc_primitives::{Hash256, Txid};
    use rbtc_psbt::{PsbtGlobal, PsbtInput, PsbtOutput};
    use std::collections::BTreeMap;

    fn make_test_psbt(fingerprint_hex: &str) -> Psbt {
        let fp_bytes = hex::decode(fingerprint_hex).unwrap();

        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256::default()),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_000,
                script_pubkey: Script::new(),
            }],
            0,
        );

        let mut bip32_derivation = BTreeMap::new();
        // Fake pubkey (33 bytes compressed)
        let pubkey = vec![0x02; 33];
        // (fingerprint, path)
        bip32_derivation.insert(pubkey, (fp_bytes, vec![44, 0, 0, 0, 0]));

        let input = PsbtInput {
            bip32_derivation,
            ..Default::default()
        };

        Psbt {
            global: PsbtGlobal {
                unsigned_tx: Some(tx),
                version: 0,
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: BTreeMap::new(),
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),
            },
            inputs: vec![input],
            outputs: vec![PsbtOutput::default()],
        }
    }

    #[test]
    fn test_external_signer_trait_definition() {
        // Verify the trait is object-safe by creating a trait object.
        let mock: Box<dyn ExternalSigner> = Box::new(MockExternalSigner {
            devices: vec![SignerDevice {
                fingerprint: "aabbccdd".to_string(),
                model: "test_device".to_string(),
            }],
            descriptors: SignerDescriptors {
                receive: vec!["wpkh([aabbccdd/84h/0h/0h]xpub.../0/*)".to_string()],
                change: vec!["wpkh([aabbccdd/84h/0h/0h]xpub.../1/*)".to_string()],
            },
            sign_result: None,
            sign_error: None,
        });

        let devices = mock.enumerate().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].fingerprint, "aabbccdd");
        assert_eq!(devices[0].model, "test_device");
    }

    #[test]
    fn test_mock_signer_enumerate() {
        let signer = MockExternalSigner {
            devices: vec![
                SignerDevice {
                    fingerprint: "11223344".to_string(),
                    model: "trezor_1".to_string(),
                },
                SignerDevice {
                    fingerprint: "55667788".to_string(),
                    model: "ledger_nano_s".to_string(),
                },
            ],
            descriptors: SignerDescriptors {
                receive: vec![],
                change: vec![],
            },
            sign_result: None,
            sign_error: None,
        };

        let devices = signer.enumerate().unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].model, "trezor_1");
        assert_eq!(devices[1].model, "ledger_nano_s");
    }

    #[test]
    fn test_mock_signer_get_descriptors() {
        let signer = MockExternalSigner {
            devices: vec![],
            descriptors: SignerDescriptors {
                receive: vec!["wpkh([aabbccdd/84h/0h/0h]xpub.../0/*)".to_string()],
                change: vec!["wpkh([aabbccdd/84h/0h/0h]xpub.../1/*)".to_string()],
            },
            sign_result: None,
            sign_error: None,
        };

        let desc = signer.get_descriptors("aabbccdd", 0).unwrap();
        assert_eq!(desc.receive.len(), 1);
        assert_eq!(desc.change.len(), 1);
        assert!(desc.receive[0].starts_with("wpkh("));
    }

    #[test]
    fn test_mock_signer_sign_psbt_matching_fingerprint() {
        let psbt = make_test_psbt("aabbccdd");

        let signer = MockExternalSigner {
            devices: vec![],
            descriptors: SignerDescriptors {
                receive: vec![],
                change: vec![],
            },
            sign_result: None,
            sign_error: None,
        };

        // Should succeed because fingerprint matches
        let result = signer.sign_psbt("aabbccdd", &psbt);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_signer_sign_psbt_fingerprint_mismatch() {
        let psbt = make_test_psbt("aabbccdd");

        let signer = MockExternalSigner {
            devices: vec![],
            descriptors: SignerDescriptors {
                receive: vec![],
                change: vec![],
            },
            sign_result: None,
            sign_error: None,
        };

        // Should fail because the PSBT has fingerprint aabbccdd but we ask
        // the signer with fingerprint 11111111
        let result = signer.sign_psbt("11111111", &psbt);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("fingerprint mismatch"));
    }

    #[test]
    fn test_mock_signer_sign_psbt_error_propagation() {
        let psbt = make_test_psbt("aabbccdd");

        let signer = MockExternalSigner {
            devices: vec![],
            descriptors: SignerDescriptors {
                receive: vec![],
                change: vec![],
            },
            sign_result: None,
            sign_error: Some("device disconnected".to_string()),
        };

        let result = signer.sign_psbt("aabbccdd", &psbt);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("device disconnected"));
    }

    #[test]
    fn test_mock_signer_returns_signed_psbt() {
        let psbt = make_test_psbt("aabbccdd");

        // Create a "signed" version with a partial sig added
        let mut signed_psbt = psbt.clone();
        signed_psbt.inputs[0]
            .partial_sigs
            .insert(vec![0x02; 33], vec![0x30; 72]);

        let signer = MockExternalSigner {
            devices: vec![],
            descriptors: SignerDescriptors {
                receive: vec![],
                change: vec![],
            },
            sign_result: Some(signed_psbt),
            sign_error: None,
        };

        let result = signer.sign_psbt("aabbccdd", &psbt).unwrap();
        // The returned PSBT should have the partial sig
        assert!(!result.inputs[0].partial_sigs.is_empty());
    }

    #[test]
    fn test_psbt_roundtrip_base64() {
        // Ensure the PSBT base64 roundtrip works (used in sign_psbt protocol)
        let psbt = make_test_psbt("aabbccdd");
        let b64 = psbt.to_base64();
        let decoded = Psbt::from_base64(&b64).unwrap();
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.outputs.len(), 1);
    }

    #[test]
    fn test_signer_chain_as_str() {
        assert_eq!(SignerChain::Main.as_str(), "main");
        assert_eq!(SignerChain::Test.as_str(), "test");
        assert_eq!(SignerChain::Regtest.as_str(), "regtest");
        assert_eq!(SignerChain::Signet.as_str(), "signet");
    }

    #[test]
    fn test_process_signer_network_args() {
        let signer =
            ProcessExternalSigner::new("hwi".to_string(), SignerChain::Test);
        let args = signer.network_args();
        assert_eq!(args, vec!["--chain", "test"]);
    }

    #[test]
    fn test_process_signer_spawn_missing_binary() {
        // Trying to spawn a nonexistent binary should give a clear error.
        let signer = ProcessExternalSigner::new(
            "/nonexistent/signer/binary".to_string(),
            SignerChain::Main,
        );
        let result = signer.enumerate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("failed to spawn"));
    }

    #[test]
    fn test_display_address_mock() {
        let signer = MockExternalSigner {
            devices: vec![],
            descriptors: SignerDescriptors {
                receive: vec![],
                change: vec![],
            },
            sign_result: None,
            sign_error: None,
        };

        let result = signer.display_address(
            "aabbccdd",
            "wpkh([aabbccdd/84h/0h/0h]02abc.../0/0)",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_taproot_fingerprint_matching() {
        // Build a PSBT with only taproot BIP32 derivation (no legacy)
        let fp_bytes = hex::decode("aabbccdd").unwrap();

        let tx = Transaction::from_parts(
            1,
            vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256::default()),
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }],
            vec![TxOut {
                value: 50_000,
                script_pubkey: Script::new(),
            }],
            0,
        );

        let mut tap_bip32 = BTreeMap::new();
        let x_only_pubkey = vec![0x02; 32];
        // (leaf_hashes, fingerprint, path)
        tap_bip32.insert(
            x_only_pubkey,
            (std::collections::BTreeSet::new(), fp_bytes, vec![86, 0, 0, 0, 0]),
        );

        let input = PsbtInput {
            tap_bip32_derivation: tap_bip32,
            ..Default::default()
        };

        let psbt = Psbt {
            global: PsbtGlobal {
                unsigned_tx: Some(tx),
                version: 0,
                tx_version: None,
                fallback_locktime: None,
                input_count: None,
                output_count: None,
                tx_modifiable: None,
                xpub: BTreeMap::new(),
                proprietary: BTreeMap::new(),
                unknown: BTreeMap::new(),
            },
            inputs: vec![input],
            outputs: vec![PsbtOutput::default()],
        };

        let signer = MockExternalSigner {
            devices: vec![],
            descriptors: SignerDescriptors {
                receive: vec![],
                change: vec![],
            },
            sign_result: None,
            sign_error: None,
        };

        // Should match via taproot derivation
        assert!(signer.sign_psbt("aabbccdd", &psbt).is_ok());
        // Should fail with wrong fingerprint
        assert!(signer.sign_psbt("11111111", &psbt).is_err());
    }
}
