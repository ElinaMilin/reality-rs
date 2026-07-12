//! VLESS request parsing for the non-encrypted (`decryption: none`) inbound.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub user_id: [u8; 16],
    pub command: u8,
    pub port: u16,
    pub destination: Destination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination { Ipv4([u8; 4]), Domain(String), Ipv6([u8; 16]) }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError { Truncated, UnsupportedVersion, UnsupportedCommand, InvalidAddress }

/// Parses the VLESS header and returns it with the number of consumed bytes.
pub fn parse_request(input: &[u8]) -> Result<(Request, usize), ParseError> {
    if input.len() < 22 { return Err(ParseError::Truncated); }
    if input[0] != 0 { return Err(ParseError::UnsupportedVersion); }
    let mut user_id = [0; 16]; user_id.copy_from_slice(&input[1..17]);
    let addons = input[17] as usize;
    let mut pos = 18usize.checked_add(addons).ok_or(ParseError::Truncated)?;
    if input.len() < pos + 4 { return Err(ParseError::Truncated); }
    let command = input[pos]; pos += 1;
    if command != 1 { return Err(ParseError::UnsupportedCommand); }
    let port = u16::from_be_bytes([input[pos], input[pos + 1]]); pos += 2;
    let destination = match input[pos] {
        1 => { pos += 1; if input.len() < pos + 4 { return Err(ParseError::Truncated); } let a = input[pos..pos+4].try_into().unwrap(); pos += 4; Destination::Ipv4(a) }
        2 => { pos += 1; if input.len() <= pos { return Err(ParseError::Truncated); } let len = input[pos] as usize; pos += 1; if input.len() < pos + len { return Err(ParseError::Truncated); } let s = std::str::from_utf8(&input[pos..pos+len]).map_err(|_| ParseError::InvalidAddress)?; if s.is_empty() { return Err(ParseError::InvalidAddress); } pos += len; Destination::Domain(s.to_owned()) }
        3 => { pos += 1; if input.len() < pos + 16 { return Err(ParseError::Truncated); } let a = input[pos..pos+16].try_into().unwrap(); pos += 16; Destination::Ipv6(a) }
        _ => return Err(ParseError::InvalidAddress),
    };
    Ok((Request { user_id, command, port, destination }, pos))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_domain_request() {
        let mut b = vec![0]; b.extend([7; 16]); b.push(0); b.push(1); b.extend(443u16.to_be_bytes()); b.push(2); b.push(11); b.extend(b"example.com");
        let (request, used) = parse_request(&b).unwrap();
        assert_eq!(used, b.len()); assert_eq!(request.port, 443); assert_eq!(request.destination, Destination::Domain("example.com".into()));
    }
}
