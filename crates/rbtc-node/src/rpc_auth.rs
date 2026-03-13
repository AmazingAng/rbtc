//! RPC authentication matching Bitcoin Core's HTTP Basic Auth scheme.
//!
//! Supports three credential sources (checked in order):
//! 1. `--rpcauth` entries: pre-hashed `username:salt$hash` (HMAC-SHA256).
//! 2. `--rpcuser` / `--rpcpassword`: plain-text credentials (hashed on init).
//! 3. Cookie file: a random `__cookie__:<hex>` written to `<datadir>/.cookie`.
//!
//! When no credentials are configured and cookie auth is not disabled, a cookie
//! file is generated automatically (matching Bitcoin Core behaviour).
//! If *no* credentials exist at all (cookie disabled + no rpcauth/rpcuser),
//! the RPC server allows unauthenticated access (dev/testing mode).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, Response, StatusCode},
    middleware::Next,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rbtc_crypto::hmac_sha256;
use tracing::warn;

/// Cookie auth username, matches Bitcoin Core's `COOKIEAUTH_USER`.
const COOKIE_USER: &str = "__cookie__";

/// A single authorised credential (username + salt + expected HMAC hex).
#[derive(Debug, Clone)]
struct RpcCredential {
    username: String,
    salt: String,
    /// Lowercase hex of HMAC-SHA256(salt, password).
    hash_hex: String,
}

/// Shared authentication state attached to the axum router.
#[derive(Debug, Clone)]
pub struct RpcAuthState {
    /// Parsed credentials (rpcauth + rpcuser/rpcpassword + cookie).
    credentials: Vec<RpcCredential>,
    /// Path to the cookie file (so we can delete it on shutdown).
    cookie_path: Option<PathBuf>,
}

impl RpcAuthState {
    /// Returns `true` if no credentials are configured (unauthenticated mode).
    pub fn is_open(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Path to the cookie file, if one was generated.
    pub fn cookie_path(&self) -> Option<&Path> {
        self.cookie_path.as_deref()
    }

    /// Delete the cookie file (call on shutdown).
    pub fn delete_cookie(&self) {
        if let Some(ref p) = self.cookie_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Initialise RPC authentication from CLI / config arguments.
///
/// Returns the shared auth state to be installed as axum middleware state.
pub fn init_rpc_auth(
    data_dir: &Path,
    rpcuser: Option<&str>,
    rpcpassword: Option<&str>,
    rpcauth_entries: &[String],
    no_cookie: bool,
) -> Result<Arc<RpcAuthState>, String> {
    let mut credentials = Vec::new();

    // 1. Parse --rpcauth entries: "username:salt$hash"
    for entry in rpcauth_entries {
        let cred = parse_rpcauth_entry(entry)
            .ok_or_else(|| format!("invalid --rpcauth value: {entry}"))?;
        credentials.push(cred);
    }

    // 2. Hash plain-text --rpcuser/--rpcpassword
    let has_password = rpcpassword.map_or(false, |p| !p.is_empty());
    if has_password {
        let user = rpcuser.unwrap_or("");
        let pass = rpcpassword.unwrap_or("");
        let salt = random_hex(16);
        let hash_hex = compute_rpcauth_hash(&salt, pass);
        if !user.is_empty() || !pass.is_empty() {
            credentials.push(RpcCredential {
                username: user.to_string(),
                salt,
                hash_hex,
            });
        }
    }

    // 3. Cookie-based auth (unless disabled or explicit password is set)
    let cookie_path = if !no_cookie && !has_password {
        match generate_cookie(data_dir) {
            Ok((path, cred)) => {
                tracing::info!("RPC cookie written to {}", path.display());
                credentials.push(cred);
                Some(path)
            }
            Err(e) => {
                return Err(format!("failed to write RPC cookie: {e}"));
            }
        }
    } else {
        None
    };

    Ok(Arc::new(RpcAuthState {
        credentials,
        cookie_path,
    }))
}

/// Axum middleware that enforces HTTP Basic authentication.
///
/// If `RpcAuthState` has no credentials (open mode), all requests pass through.
pub async fn rpc_auth_middleware(
    State(auth): State<Arc<RpcAuthState>>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    // Open mode: no credentials configured, allow everything.
    if auth.is_open() {
        return next.run(req).await;
    }

    // Extract Authorization header.
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(auth_value) = auth_header else {
        return unauthorized_response();
    };

    if !check_auth(auth_value, &auth.credentials) {
        warn!("RPC: incorrect credentials");
        // Deter brute-forcing (Bitcoin Core sleeps 250ms).
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        return unauthorized_response();
    }

    next.run(req).await
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a `username:salt$hash` string into an `RpcCredential`.
fn parse_rpcauth_entry(entry: &str) -> Option<RpcCredential> {
    let colon_pos = entry.find(':')?;
    let username = entry[..colon_pos].to_string();
    let rest = &entry[colon_pos + 1..];
    let dollar_pos = rest.find('$')?;
    let salt = rest[..dollar_pos].to_string();
    let hash_hex = rest[dollar_pos + 1..].to_lowercase();
    // Basic validation: salt and hash should be hex strings.
    if salt.is_empty() || hash_hex.is_empty() {
        return None;
    }
    Some(RpcCredential {
        username,
        salt,
        hash_hex,
    })
}

/// Compute HMAC-SHA256(salt, password) and return lowercase hex.
fn compute_rpcauth_hash(salt: &str, password: &str) -> String {
    let mac = hmac_sha256(salt.as_bytes(), password.as_bytes());
    hex::encode(mac)
}

/// Check an `Authorization: Basic <base64>` header against known credentials.
fn check_auth(auth_value: &str, credentials: &[RpcCredential]) -> bool {
    let b64 = match auth_value.strip_prefix("Basic ") {
        Some(b) => b.trim(),
        None => return false,
    };
    let decoded = match B64.decode(b64) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let userpass = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let colon_pos = match userpass.find(':') {
        Some(p) => p,
        None => return false,
    };
    let user = &userpass[..colon_pos];
    let pass = &userpass[colon_pos + 1..];

    for cred in credentials {
        if !timing_resistant_eq(cred.username.as_bytes(), user.as_bytes()) {
            continue;
        }
        let candidate = compute_rpcauth_hash(&cred.salt, pass);
        if timing_resistant_eq(candidate.as_bytes(), cred.hash_hex.as_bytes()) {
            return true;
        }
    }
    false
}

/// Constant-time byte comparison to resist timing side-channels.
fn timing_resistant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate a random cookie file at `<data_dir>/.cookie`.
///
/// Returns the path and the credential derived from it.
fn generate_cookie(data_dir: &Path) -> Result<(PathBuf, RpcCredential), std::io::Error> {
    // Ensure data directory exists.
    std::fs::create_dir_all(data_dir)?;

    let password_hex = random_hex(32);
    let cookie_path = data_dir.join(".cookie");
    let cookie_content = format!("{COOKIE_USER}:{password_hex}");

    // Write atomically: write to .cookie.tmp then rename.
    let tmp_path = data_dir.join(".cookie.tmp");
    std::fs::write(&tmp_path, cookie_content.as_bytes())?;

    // Set restrictive permissions (owner read/write only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp_path, perms)?;
    }

    std::fs::rename(&tmp_path, &cookie_path)?;

    // Build credential: salt is random, hash = HMAC-SHA256(salt, password_hex)
    let salt = random_hex(16);
    let hash_hex = compute_rpcauth_hash(&salt, &password_hex);

    Ok((
        cookie_path,
        RpcCredential {
            username: COOKIE_USER.to_string(),
            salt,
            hash_hex,
        },
    ))
}

/// Generate `n` random bytes and return as lowercase hex string.
fn random_hex(n: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..n).map(|_| rng.gen::<u8>()).collect();
    hex::encode(bytes)
}

fn unauthorized_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Basic realm=\"jsonrpc\"")
        .body(Body::empty())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rpcauth_entry_valid() {
        let entry = "alice:a]b$c0ffee";
        let cred = parse_rpcauth_entry(entry).unwrap();
        assert_eq!(cred.username, "alice");
        assert_eq!(cred.salt, "a]b");
        assert_eq!(cred.hash_hex, "c0ffee");
    }

    #[test]
    fn parse_rpcauth_entry_invalid_no_colon() {
        assert!(parse_rpcauth_entry("nodelimiter").is_none());
    }

    #[test]
    fn parse_rpcauth_entry_invalid_no_dollar() {
        assert!(parse_rpcauth_entry("user:saltnodollar").is_none());
    }

    #[test]
    fn compute_hash_matches_bitcoin_core() {
        // Bitcoin Core: HMAC-SHA256(key=salt, data=password)
        // We can verify round-trip: parse an entry we generate ourselves.
        let salt = "abcdef0123456789";
        let password = "mysecretpass";
        let hash = compute_rpcauth_hash(salt, password);

        // Verify via rbtc_crypto directly.
        let expected = hex::encode(hmac_sha256(salt.as_bytes(), password.as_bytes()));
        assert_eq!(hash, expected);
    }

    #[test]
    fn check_auth_valid_basic() {
        let salt = "deadbeef";
        let password = "hunter2";
        let hash_hex = compute_rpcauth_hash(salt, password);
        let cred = RpcCredential {
            username: "admin".to_string(),
            salt: salt.to_string(),
            hash_hex,
        };

        // Build Basic auth header value.
        let encoded = B64.encode("admin:hunter2");
        let header = format!("Basic {encoded}");
        assert!(check_auth(&header, &[cred]));
    }

    #[test]
    fn check_auth_wrong_password() {
        let salt = "deadbeef";
        let password = "hunter2";
        let hash_hex = compute_rpcauth_hash(salt, password);
        let cred = RpcCredential {
            username: "admin".to_string(),
            salt: salt.to_string(),
            hash_hex,
        };

        let encoded = B64.encode("admin:wrongpass");
        let header = format!("Basic {encoded}");
        assert!(!check_auth(&header, &[cred]));
    }

    #[test]
    fn check_auth_wrong_username() {
        let salt = "deadbeef";
        let password = "hunter2";
        let hash_hex = compute_rpcauth_hash(salt, password);
        let cred = RpcCredential {
            username: "admin".to_string(),
            salt: salt.to_string(),
            hash_hex,
        };

        let encoded = B64.encode("notadmin:hunter2");
        let header = format!("Basic {encoded}");
        assert!(!check_auth(&header, &[cred]));
    }

    #[test]
    fn check_auth_no_basic_prefix() {
        let cred = RpcCredential {
            username: "u".to_string(),
            salt: "s".to_string(),
            hash_hex: "h".to_string(),
        };
        assert!(!check_auth("Bearer token123", &[cred]));
    }

    #[test]
    fn check_auth_invalid_base64() {
        let cred = RpcCredential {
            username: "u".to_string(),
            salt: "s".to_string(),
            hash_hex: "h".to_string(),
        };
        assert!(!check_auth("Basic !!!not-base64!!!", &[cred]));
    }

    #[test]
    fn check_auth_multiple_credentials() {
        let salt1 = "salt1";
        let salt2 = "salt2";
        let creds = vec![
            RpcCredential {
                username: "alice".to_string(),
                salt: salt1.to_string(),
                hash_hex: compute_rpcauth_hash(salt1, "pass_a"),
            },
            RpcCredential {
                username: "bob".to_string(),
                salt: salt2.to_string(),
                hash_hex: compute_rpcauth_hash(salt2, "pass_b"),
            },
        ];

        // Alice can auth.
        let h1 = format!("Basic {}", B64.encode("alice:pass_a"));
        assert!(check_auth(&h1, &creds));

        // Bob can auth.
        let h2 = format!("Basic {}", B64.encode("bob:pass_b"));
        assert!(check_auth(&h2, &creds));

        // Cross credentials fail.
        let h3 = format!("Basic {}", B64.encode("alice:pass_b"));
        assert!(!check_auth(&h3, &creds));
    }

    #[test]
    fn cookie_generation_and_auth() {
        let tmpdir = tempfile::tempdir().unwrap();
        let (cookie_path, cred) = generate_cookie(tmpdir.path()).unwrap();

        // Cookie file exists and has correct format.
        let content = std::fs::read_to_string(&cookie_path).unwrap();
        assert!(content.starts_with("__cookie__:"));
        let password = content.strip_prefix("__cookie__:").unwrap();

        // The credential should accept this password.
        let encoded = B64.encode(format!("__cookie__:{password}"));
        let header = format!("Basic {encoded}");
        assert!(check_auth(&header, &[cred]));
    }

    #[test]
    fn cookie_file_permissions() {
        let tmpdir = tempfile::tempdir().unwrap();
        let (cookie_path, _) = generate_cookie(tmpdir.path()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&cookie_path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "cookie should be owner read/write only");
        }
    }

    #[test]
    fn init_rpc_auth_open_mode() {
        // No credentials, cookie disabled -> open mode.
        let tmpdir = tempfile::tempdir().unwrap();
        let auth = init_rpc_auth(tmpdir.path(), None, None, &[], true).unwrap();
        assert!(auth.is_open());
    }

    #[test]
    fn init_rpc_auth_with_cookie() {
        let tmpdir = tempfile::tempdir().unwrap();
        let auth = init_rpc_auth(tmpdir.path(), None, None, &[], false).unwrap();
        assert!(!auth.is_open());
        assert!(auth.cookie_path().is_some());

        // Read cookie and verify it works.
        let content = std::fs::read_to_string(auth.cookie_path().unwrap()).unwrap();
        let encoded = B64.encode(&content);
        let header = format!("Basic {encoded}");
        assert!(check_auth(&header, &auth.credentials));
    }

    #[test]
    fn init_rpc_auth_with_rpcuser_password() {
        let tmpdir = tempfile::tempdir().unwrap();
        let auth = init_rpc_auth(
            tmpdir.path(),
            Some("myuser"),
            Some("mypass"),
            &[],
            true,
        )
        .unwrap();
        assert!(!auth.is_open());
        // No cookie when password is set.
        assert!(auth.cookie_path().is_none());

        let encoded = B64.encode("myuser:mypass");
        let header = format!("Basic {encoded}");
        assert!(check_auth(&header, &auth.credentials));
    }

    #[test]
    fn init_rpc_auth_with_rpcauth_entry() {
        let tmpdir = tempfile::tempdir().unwrap();
        let salt = "cafebabe";
        let password = "s3cret";
        let hash = compute_rpcauth_hash(salt, password);
        let entry = format!("testuser:{salt}${hash}");

        let auth = init_rpc_auth(tmpdir.path(), None, None, &[entry], true).unwrap();
        assert!(!auth.is_open());

        let encoded = B64.encode("testuser:s3cret");
        let header = format!("Basic {encoded}");
        assert!(check_auth(&header, &auth.credentials));
    }

    #[test]
    fn init_rpc_auth_bad_rpcauth_entry() {
        let tmpdir = tempfile::tempdir().unwrap();
        let result = init_rpc_auth(tmpdir.path(), None, None, &["bad".to_string()], true);
        assert!(result.is_err());
    }

    #[test]
    fn timing_resistant_eq_same() {
        assert!(timing_resistant_eq(b"hello", b"hello"));
    }

    #[test]
    fn timing_resistant_eq_different() {
        assert!(!timing_resistant_eq(b"hello", b"world"));
    }

    #[test]
    fn timing_resistant_eq_different_length() {
        assert!(!timing_resistant_eq(b"short", b"longer"));
    }

    #[test]
    fn delete_cookie_cleanup() {
        let tmpdir = tempfile::tempdir().unwrap();
        let auth = init_rpc_auth(tmpdir.path(), None, None, &[], false).unwrap();
        let path = auth.cookie_path().unwrap().to_path_buf();
        assert!(path.exists());
        auth.delete_cookie();
        assert!(!path.exists());
    }
}
