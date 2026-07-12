//! Strict, allocation-bounded TLS 1.3 ClientHello parsing used by REALITY.
//!
//! This is deliberately a parser, not a general TLS implementation. It only
//! extracts the fields that REALITY authenticates before the TLS 1.3 state
//! machine takes ownership of the connection.

pub const TLS_HANDSHAKE_RECORD: u8 = 22;
pub const CLIENT_HELLO: u8 = 1;
pub const TLS13: u16 = 0x0304;
pub const X25519: u16 = 0x001d;
/// Go/Xray's TLS 1.3 hybrid group. REALITY authenticates using its trailing
/// X25519 public key while the TLS handshake also processes the ML-KEM share.
pub const X25519_MLKEM768: u16 = 0x11ec;
pub const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1_184;
const SNI_EXTENSION: u16 = 0;
const SUPPORTED_VERSIONS_EXTENSION: u16 = 43;
const KEY_SHARE_EXTENSION: u16 = 51;
const MAX_CLIENT_HELLO: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Raw TLS handshake message (type + u24 length + body), without record
    /// headers. This is the input to TLS transcript hashing.
    pub raw: Vec<u8>,
    /// REALITY's AES-GCM associated data representation. Xray clears the
    /// session-ID bytes before authenticating the ClientHello.
    pub reality_aad: Vec<u8>,
    pub random: [u8; 32],
    pub server_name: String,
    pub x25519_key_share: Option<[u8; 32]>,
    /// Every X25519 component offered by the client, including the trailing
    /// X25519 component of hybrid shares. uTLS fingerprints may offer more
    /// than one representation.
    pub x25519_key_shares: Vec<[u8; 32]>,
    pub encrypted_session_id: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    InvalidRecord,
    InvalidHandshake,
    TooLarge,
    UnsupportedVersion,
    InvalidExtension,
    MissingServerName,
}

pub fn parse_record(record: &[u8]) -> Result<ClientHello, ParseError> {
    if record.len() < 5 { return Err(ParseError::Truncated); }
    if record[0] != TLS_HANDSHAKE_RECORD { return Err(ParseError::InvalidRecord); }
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    if len > MAX_CLIENT_HELLO { return Err(ParseError::TooLarge); }
    if record.len() != len + 5 { return Err(ParseError::Truncated); }
    parse_handshake(&record[5..])
}

pub fn parse_handshake(raw: &[u8]) -> Result<ClientHello, ParseError> {
    if raw.len() < 4 { return Err(ParseError::Truncated); }
    if raw[0] != CLIENT_HELLO { return Err(ParseError::InvalidHandshake); }
    let body_len = u24(&raw[1..4]);
    if body_len > MAX_CLIENT_HELLO { return Err(ParseError::TooLarge); }
    if raw.len() != body_len + 4 { return Err(ParseError::Truncated); }
    let body = &raw[4..];
    if body.len() < 35 { return Err(ParseError::Truncated); }
    let mut random = [0; 32]; random.copy_from_slice(&body[2..34]);
    let sid_len = body[34] as usize;
    let sid_start: usize = 35;
    let sid_end = sid_start.checked_add(sid_len).ok_or(ParseError::Truncated)?;
    if sid_end > body.len() { return Err(ParseError::Truncated); }
    let encrypted_session_id = body[sid_start..sid_end].to_vec();
    let mut p = sid_end;
    let suites_len = read_u16(body, &mut p)? as usize;
    p = p.checked_add(suites_len).ok_or(ParseError::Truncated)?;
    if suites_len == 0 || p > body.len() { return Err(ParseError::Truncated); }
    let compression_len = *body.get(p).ok_or(ParseError::Truncated)? as usize; p += 1;
    p = p.checked_add(compression_len).ok_or(ParseError::Truncated)?;
    if p > body.len() { return Err(ParseError::Truncated); }
    let extensions_len = read_u16(body, &mut p)? as usize;
    let extensions_end = p.checked_add(extensions_len).ok_or(ParseError::Truncated)?;
    if extensions_end != body.len() { return Err(ParseError::InvalidExtension); }

    let mut server_name = None;
    let mut tls13 = false;
    let mut x25519_key_shares = Vec::new();
    while p < extensions_end {
        let ty = read_u16(body, &mut p)?;
        let len = read_u16(body, &mut p)? as usize;
        let end = p.checked_add(len).ok_or(ParseError::Truncated)?;
        if end > extensions_end { return Err(ParseError::InvalidExtension); }
        match ty {
            SNI_EXTENSION => server_name = parse_sni(&body[p..end])?,
            SUPPORTED_VERSIONS_EXTENSION => tls13 = parse_supported_versions(&body[p..end])?,
            KEY_SHARE_EXTENSION => x25519_key_shares = parse_key_share(&body[p..end])?,
            _ => {}
        }
        p = end;
    }
    if !tls13 { return Err(ParseError::UnsupportedVersion); }
    let server_name = server_name.ok_or(ParseError::MissingServerName)?;
    let mut reality_aad = raw.to_vec();
    // Raw offset = handshake header (4) + legacy version (2) + random (32) +
    // session-ID length byte (1). This is the same offset used by Xray.
    reality_aad[39..39 + sid_len].fill(0);
    let x25519_key_share = x25519_key_shares.first().copied();
    Ok(ClientHello { raw: raw.to_vec(), reality_aad, random, server_name, x25519_key_share, x25519_key_shares, encrypted_session_id })
}

fn parse_sni(data: &[u8]) -> Result<Option<String>, ParseError> {
    if data.len() < 2 { return Err(ParseError::InvalidExtension); }
    let total = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if total + 2 != data.len() { return Err(ParseError::InvalidExtension); }
    let mut p = 2;
    while p < data.len() {
        let ty = *data.get(p).ok_or(ParseError::InvalidExtension)?; p += 1;
        let len = read_u16(data, &mut p)? as usize;
        let end = p.checked_add(len).ok_or(ParseError::InvalidExtension)?;
        if end > data.len() { return Err(ParseError::InvalidExtension); }
        if ty == 0 {
            let name = std::str::from_utf8(&data[p..end]).map_err(|_| ParseError::InvalidExtension)?;
            if name.is_empty() { return Err(ParseError::InvalidExtension); }
            return Ok(Some(name.to_ascii_lowercase()));
        }
        p = end;
    }
    Ok(None)
}

fn parse_supported_versions(data: &[u8]) -> Result<bool, ParseError> {
    let Some((&len, rest)) = data.split_first() else { return Err(ParseError::InvalidExtension); };
    if len as usize != rest.len() || rest.len() % 2 != 0 { return Err(ParseError::InvalidExtension); }
    Ok(rest.chunks_exact(2).any(|v| u16::from_be_bytes([v[0], v[1]]) == TLS13))
}

fn parse_key_share(data: &[u8]) -> Result<Vec<[u8; 32]>, ParseError> {
    if data.len() < 2 { return Err(ParseError::InvalidExtension); }
    let total = usize::from(u16::from_be_bytes([data[0], data[1]]));
    if total + 2 != data.len() { return Err(ParseError::InvalidExtension); }
    let mut p = 2;
    let mut shares = Vec::new();
    while p < data.len() {
        let group = read_u16(data, &mut p)?;
        let len = read_u16(data, &mut p)? as usize;
        let end = p.checked_add(len).ok_or(ParseError::InvalidExtension)?;
        if end > data.len() { return Err(ParseError::InvalidExtension); }
        if group == X25519 && len == 32 { shares.push(data[p..end].try_into().unwrap()); }
        if group == X25519_MLKEM768 && len == MLKEM768_ENCAPSULATION_KEY_LEN + 32 {
            shares.push(data[end - 32..end].try_into().unwrap());
        }
        p = end;
    }
    Ok(shares)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16, ParseError> {
    let end = pos.checked_add(2).ok_or(ParseError::Truncated)?;
    let bytes: [u8; 2] = data.get(*pos..end).ok_or(ParseError::Truncated)?.try_into().unwrap();
    *pos = end; Ok(u16::from_be_bytes(bytes))
}
fn u24(data: &[u8]) -> usize { (usize::from(data[0]) << 16) | (usize::from(data[1]) << 8) | usize::from(data[2]) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_tls13_x25519_hello_and_clears_session_id_for_aad() {
        let mut body = vec![0x03, 0x03]; body.extend([9; 32]); body.push(32); body.extend([7; 32]);
        body.extend(2u16.to_be_bytes()); body.extend(0x1301u16.to_be_bytes()); body.extend([1, 0]);
        let mut ext = vec![];
        ext.extend(0u16.to_be_bytes()); ext.extend(16u16.to_be_bytes()); ext.extend(14u16.to_be_bytes()); ext.push(0); ext.extend(11u16.to_be_bytes()); ext.extend(b"example.com");
        ext.extend(43u16.to_be_bytes()); ext.extend(3u16.to_be_bytes()); ext.extend([2, 0x03, 0x04]);
        ext.extend(51u16.to_be_bytes()); ext.extend(38u16.to_be_bytes()); ext.extend(36u16.to_be_bytes()); ext.extend(X25519.to_be_bytes()); ext.extend(32u16.to_be_bytes()); ext.extend([8; 32]);
        body.extend((ext.len() as u16).to_be_bytes()); body.extend(ext);
        let mut hello = vec![CLIENT_HELLO, 0, 0, body.len() as u8]; hello.extend(body);
        let parsed = parse_handshake(&hello).unwrap();
        assert_eq!(parsed.server_name, "example.com"); assert_eq!(parsed.x25519_key_share, Some([8; 32]));
        assert!(parsed.reality_aad[39..71].iter().all(|b| *b == 0)); assert!(parsed.raw[39..71].iter().all(|b| *b == 7));
    }
}
