use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signer as DalekSigner};
use hmac::{Hmac, Mac};
use reality_rs::{reality::{authenticate_client_hello, ServerConfig}, tls_client_hello::parse_record, vless::{parse_request, Destination, ParseError as VlessError}};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::{pki_types::CertificateDer, sign::{CertifiedKey, Signer, SigningKey}, server::{ClientHello as RustlsClientHello, ResolvesServerCert}, Error as TlsError, ServerConfig as TlsServerConfig, SignatureAlgorithm, SignatureScheme};
use serde::Deserialize;
use sha2::Sha512;
use std::{collections::BTreeSet, env, io, pin::Pin, sync::Arc, task::{Context, Poll}};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf}, net::{TcpListener, TcpStream}};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

type HmacSha512 = Hmac<Sha512>;

#[derive(Deserialize)]
struct FileConfig { listen: String, users: Vec<String>, reality: RealityFileConfig }
#[derive(Deserialize)]
struct RealityFileConfig {
    private_key: String, server_names: Vec<String>, short_ids: Vec<String>,
    #[serde(default)] min_client_version: Option<[u8; 3]>,
    #[serde(default)] max_client_version: Option<[u8; 3]>,
    #[serde(default = "default_time_diff")] max_time_diff_secs: u64,
    fallback: String,
}
fn default_time_diff() -> u64 { 600 }

struct RuntimeConfig { listen: String, users: BTreeSet<[u8; 16]>, reality: ServerConfig, fallback: String }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "failed to install the rustls ring crypto provider")?;
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("keygen") => {
            let private = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
            let public = x25519_dalek::PublicKey::from(&private);
            println!("private_key={}", URL_SAFE_NO_PAD.encode(private.to_bytes()));
            println!("public_key={}", URL_SAFE_NO_PAD.encode(public.as_bytes()));
            Ok(())
        }
        Some("serve") => {
            let path = args.next().ok_or("usage: reality-rs serve <config.json>")?;
            serve(load_config(&path).await?).await
        }
        Some("test-http") => serve_test_http(args.next().as_deref().unwrap_or("127.0.0.1:18080")).await,
        _ => Err("usage: reality-rs <serve <config.json>|keygen>".into()),
    }
}

async fn serve_test_http(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(address).await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut request = [0; 1024]; let _ = stream.read(&mut request).await;
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nrelay-ok").await;
        });
    }
}

async fn load_config(path: &str) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    let raw: FileConfig = serde_json::from_slice(&tokio::fs::read(path).await?)?;
    let private_key: [u8; 32] = URL_SAFE_NO_PAD.decode(raw.reality.private_key)?.try_into().map_err(|_| "private_key must decode to 32 bytes")?;
    let server_names = raw.reality.server_names.into_iter().map(|n| n.to_ascii_lowercase()).collect();
    let short_ids = raw.reality.short_ids.into_iter().map(|id| parse_short_id(&id)).collect::<Result<BTreeSet<_>, _>>()?;
    let users = raw.users.into_iter().map(|id| Ok(*Uuid::parse_str(&id)?.as_bytes())).collect::<Result<BTreeSet<_>, Box<dyn std::error::Error>>>()?;
    if users.is_empty() || short_ids.is_empty() { return Err("users and short_ids must not be empty".into()); }
    Ok(RuntimeConfig { listen: raw.listen, users, fallback: raw.reality.fallback, reality: ServerConfig { private_key, server_names, short_ids, min_client_version: raw.reality.min_client_version, max_client_version: raw.reality.max_client_version, max_time_diff_secs: raw.reality.max_time_diff_secs } })
}
fn parse_short_id(input: &str) -> Result<[u8; 8], Box<dyn std::error::Error>> {
    if input.len() > 16 || input.len() % 2 != 0 { return Err("short_id must be 0-16 hex chars".into()); }
    let mut result = [0; 8];
    for (index, pair) in input.as_bytes().chunks(2).enumerate() { result[index] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?; }
    Ok(result)
}

async fn serve(config: RuntimeConfig) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&config.listen).await?;
    eprintln!("reality-rs listening on {}", config.listen);
    let config = Arc::new(config);
    loop { let (stream, _) = listener.accept().await?; let config = Arc::clone(&config); tokio::spawn(async move { if let Err(error) = handle(stream, config).await { eprintln!("connection failed: {error}"); } }); }
}

async fn handle(mut stream: TcpStream, config: Arc<RuntimeConfig>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let record = read_first_record(&mut stream).await?;
    let hello = match parse_record(&record) {
        Ok(hello) => hello,
        Err(error) => { eprintln!("reality rejected ClientHello: {error:?}"); return fallback(stream, record, &config.fallback).await; }
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let (authenticated, client_key_share) = match hello.x25519_key_shares.iter().find_map(|share| {
        authenticate_client_hello(&config.reality, &hello.server_name, &hello.random, Some(*share), &hello.encrypted_session_id, &hello.reality_aad, now).ok().map(|client| (client, *share))
    }) {
        Some(value) => value,
        None => {
            eprintln!("reality authentication failed for {} X25519 key shares", hello.x25519_key_shares.len());
            return fallback(stream, record, &config.fallback).await;
        }
    };
    let acceptor = TlsAcceptor::from(Arc::new(make_tls_config(&hello.server_name, &authentication_key(&config.reality.private_key, &hello, client_key_share)?)?));
    let mut tls = acceptor.accept(ReplayStream { prefix: record, inner: stream }).await?;
    let (request, initial_payload) = read_vless_request(&mut tls).await?;
    if !config.users.contains(&request.user_id) { return Err("unknown VLESS user".into()); }
    tls.write_all(&[0, 0]).await?; // VLESS response: version 0, no addons.
    let target = destination(&request.destination, request.port)?;
    let mut outbound = TcpStream::connect(target).await?;
    if !initial_payload.is_empty() { outbound.write_all(&initial_payload).await?; }
    let _ = authenticated; // Kept until connection authentication completes.
    tokio::io::copy_bidirectional(&mut tls, &mut outbound).await?;
    Ok(())
}

fn authentication_key(private_key: &[u8; 32], hello: &reality_rs::tls_client_hello::ClientHello, peer: [u8; 32]) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    use hkdf::Hkdf; use sha2::Sha256; use x25519_dalek::{PublicKey, StaticSecret};
    let shared = StaticSecret::from(*private_key).diffie_hellman(&PublicKey::from(peer));
    let hk = Hkdf::<Sha256>::new(Some(&hello.random[..20]), shared.as_bytes()); let mut key = [0; 32]; hk.expand(b"REALITY", &mut key).map_err(|_| "hkdf failed")?; Ok(key)
}

fn make_tls_config(name: &str, auth_key: &[u8; 32]) -> Result<TlsServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
    let params = CertificateParams::new(vec![name.to_owned()])?;
    let cert = params.self_signed(&key_pair)?;
    let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(&key_pair.serialize_der())?;
    let mut der = cert.der().to_vec();
    let mut mac = HmacSha512::new_from_slice(auth_key)?; mac.update(signing_key.verifying_key().as_bytes());
    let signature_offset = der.len() - 64;
    der[signature_offset..].copy_from_slice(&mac.finalize().into_bytes());
    let certified = Arc::new(CertifiedKey::new(vec![CertificateDer::from(der)], Arc::new(ForcedEd25519Key(Arc::new(signing_key)))));
    let config = TlsServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(FixedCertResolver(certified)));
    Ok(config)
}

/// REALITY's temporary certificate is Ed25519 even when uTLS fingerprints omit
/// ED25519 from their advertised signature schemes. Xray's REALITY server
/// follows this rule; this signer mirrors that behaviour for compatibility.
#[derive(Debug)]
struct ForcedEd25519Key(Arc<ed25519_dalek::SigningKey>);
#[derive(Debug)]
struct ForcedEd25519Signer(Arc<ed25519_dalek::SigningKey>);
impl SigningKey for ForcedEd25519Key {
    fn choose_scheme(&self, _: &[SignatureScheme]) -> Option<Box<dyn Signer>> { Some(Box::new(ForcedEd25519Signer(Arc::clone(&self.0)))) }
    fn algorithm(&self) -> SignatureAlgorithm { SignatureAlgorithm::ED25519 }
}
impl Signer for ForcedEd25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> { Ok(self.0.sign(message).to_bytes().to_vec()) }
    fn scheme(&self) -> SignatureScheme { SignatureScheme::ED25519 }
}
#[derive(Debug)]
struct FixedCertResolver(Arc<CertifiedKey>);
impl ResolvesServerCert for FixedCertResolver {
    fn resolve(&self, _: RustlsClientHello<'_>) -> Option<Arc<CertifiedKey>> { Some(Arc::clone(&self.0)) }
}

async fn read_first_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> { let mut header = [0; 5]; stream.read_exact(&mut header).await?; let len = usize::from(u16::from_be_bytes([header[3], header[4]])); if len > 65_536 { return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized TLS record")); } let mut record = header.to_vec(); record.resize(5 + len, 0); stream.read_exact(&mut record[5..]).await?; Ok(record) }
async fn fallback(mut stream: TcpStream, record: Vec<u8>, target: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> { let mut target = TcpStream::connect(target).await?; target.write_all(&record).await?; tokio::io::copy_bidirectional(&mut stream, &mut target).await?; Ok(()) }
async fn read_vless_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(reality_rs::vless::Request, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> { let mut bytes = vec![0; 512]; let mut end = 0; loop { let n = stream.read(&mut bytes[end..]).await?; if n == 0 { return Err("connection closed before VLESS request".into()); } end += n; match parse_request(&bytes[..end]) { Ok((request, used)) => return Ok((request, bytes[used..end].to_vec())), Err(VlessError::Truncated) if end < bytes.len() => continue, Err(error) => return Err(format!("invalid VLESS request: {error:?}").into()), } } }
fn destination(destination: &Destination, port: u16) -> Result<String, Box<dyn std::error::Error + Send + Sync>> { Ok(match destination { Destination::Domain(host) => format!("{host}:{port}"), Destination::Ipv4(ip) => format!("{}.{}.{}.{}:{port}", ip[0], ip[1], ip[2], ip[3]), Destination::Ipv6(ip) => format!("[{}]:{port}", std::net::Ipv6Addr::from(*ip)), }) }

struct ReplayStream { prefix: Vec<u8>, inner: TcpStream }
impl AsyncRead for ReplayStream { fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { if !self.prefix.is_empty() { let amount = self.prefix.len().min(buf.remaining()); let bytes: Vec<u8> = self.prefix.drain(..amount).collect(); buf.put_slice(&bytes); return Poll::Ready(Ok(())); } Pin::new(&mut self.inner).poll_read(cx, buf) } }
impl AsyncWrite for ReplayStream { fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> { Pin::new(&mut self.inner).poll_write(cx, data) } fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) } fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) } }
