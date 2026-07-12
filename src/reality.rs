use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeSet;
use x25519_dalek::{PublicKey, StaticSecret};

/// Fixed layout carried in a REALITY TLS ClientHello session ID before AEAD
/// encryption: Xray version (3), reserved byte, UNIX time (u32 BE), and an
/// eight-byte short ID. The remaining bytes are protocol padding.
pub const SESSION_ID_LEN: usize = 32;
pub const REALITY_LABEL: &[u8] = b"REALITY";

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub private_key: [u8; 32],
    pub server_names: BTreeSet<String>,
    pub short_ids: BTreeSet<[u8; 8]>,
    pub min_client_version: Option<[u8; 3]>,
    pub max_client_version: Option<[u8; 3]>,
    /// Zero disables timestamp validation, matching Xray's `maxTimeDiff`.
    pub max_time_diff_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedClient {
    pub version: [u8; 3],
    pub unix_time: u32,
    pub short_id: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationError {
    ServerName,
    MissingX25519KeyShare,
    InvalidSessionId,
    Crypto,
    Version,
    ClockSkew,
    ShortId,
}

/// Authenticates the REALITY material embedded in an already parsed TLS 1.3
/// ClientHello. `client_random` must be the 32 raw ClientHello random bytes.
pub fn authenticate_client_hello(
    config: &ServerConfig,
    server_name: &str,
    client_random: &[u8; 32],
    client_x25519_public: Option<[u8; 32]>,
    encrypted_session_id: &[u8],
    // The ClientHello wire image after the session-ID field has been cleared,
    // exactly as Xray's server-side REALITY implementation supplies it to
    // AES-GCM as associated data.
    client_hello_aad: &[u8],
    now_unix: u64,
) -> Result<AuthenticatedClient, AuthenticationError> {
    if !config.server_names.contains(server_name) { return Err(AuthenticationError::ServerName); }
    let peer = client_x25519_public.ok_or(AuthenticationError::MissingX25519KeyShare)?;
    if encrypted_session_id.len() != SESSION_ID_LEN { return Err(AuthenticationError::InvalidSessionId); }

    let secret = StaticSecret::from(config.private_key);
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared.as_bytes());
    let mut auth_key = [0u8; 32];
    hk.expand(REALITY_LABEL, &mut auth_key).map_err(|_| AuthenticationError::Crypto)?;

    // Xray uses the final 12 bytes of ClientHello.random as the AES-GCM nonce
    // and authenticates the ClientHello wire image as associated data.
    decrypt_session_id_with_aad(&auth_key, client_random, encrypted_session_id, client_hello_aad)
        .and_then(|plain| validate_plaintext(config, &plain, now_unix))
}

pub fn decrypt_session_id_with_aad(
    auth_key: &[u8; 32], client_random: &[u8; 32], encrypted: &[u8], aad: &[u8],
) -> Result<[u8; SESSION_ID_LEN], AuthenticationError> {
    if encrypted.len() != SESSION_ID_LEN { return Err(AuthenticationError::InvalidSessionId); }
    let cipher = Aes256Gcm::new_from_slice(auth_key).map_err(|_| AuthenticationError::Crypto)?;
    let mut value = encrypted.to_vec();
    cipher.decrypt_in_place(Nonce::from_slice(&client_random[20..]), aad, &mut value)
        .map_err(|_| AuthenticationError::Crypto)?;
    if value.len() != 16 { return Err(AuthenticationError::InvalidSessionId); }
    let mut plain = [0u8; SESSION_ID_LEN];
    plain[..16].copy_from_slice(&value);
    Ok(plain)
}

fn validate_plaintext(config: &ServerConfig, plain: &[u8; SESSION_ID_LEN], now: u64)
    -> Result<AuthenticatedClient, AuthenticationError> {
    let version = [plain[0], plain[1], plain[2]];
    if config.min_client_version.is_some_and(|min| version < min) ||
        config.max_client_version.is_some_and(|max| version > max) { return Err(AuthenticationError::Version); }
    let unix_time = u32::from_be_bytes(plain[4..8].try_into().unwrap());
    if config.max_time_diff_secs != 0 && now.abs_diff(u64::from(unix_time)) > config.max_time_diff_secs {
        return Err(AuthenticationError::ClockSkew);
    }
    let short_id: [u8; 8] = plain[8..16].try_into().unwrap();
    if !config.short_ids.contains(&short_id) { return Err(AuthenticationError::ShortId); }
    Ok(AuthenticatedClient { version, unix_time, short_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use rand_core::OsRng;

    #[test]
    fn accepts_an_xray_layout_session_id() {
        let server = StaticSecret::random_from_rng(OsRng);
        let client = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client);
        let random = [3u8; 32];
        let aad = b"client-hello-with-cleared-session-id";
        let short_id = [0xab; 8];
        let mut plain = [0u8; 16];
        plain[..3].copy_from_slice(&[1, 2, 3]); plain[4..8].copy_from_slice(&1_700_000_000u32.to_be_bytes()); plain[8..].copy_from_slice(&short_id);
        let shared = client.diffie_hellman(&PublicKey::from(&server));
        let hk = Hkdf::<Sha256>::new(Some(&random[..20]), shared.as_bytes());
        let mut key = [0u8; 32]; hk.expand(REALITY_LABEL, &mut key).unwrap();
        let encrypted = Aes256Gcm::new_from_slice(&key).unwrap().encrypt(Nonce::from_slice(&random[20..]), aes_gcm::aead::Payload { msg: &plain, aad }).unwrap();
        let config = ServerConfig { private_key: server.to_bytes(), server_names: ["example.com".to_owned()].into_iter().collect(), short_ids: [short_id].into_iter().collect(), min_client_version: None, max_client_version: None, max_time_diff_secs: 60 };
        let authenticated = authenticate_client_hello(&config, "example.com", &random, Some(client_public.to_bytes()), &encrypted, aad, 1_700_000_000).unwrap();
        assert_eq!(authenticated.version, [1, 2, 3]); assert_eq!(authenticated.short_id, short_id);
    }
}
