use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::sync::Arc;
use rustls::{ServerConfig, ClientConfig};

use tokio_rustls::{TlsAcceptor, TlsConnector};
use rustls::server::WebPkiClientVerifier;
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, PrivatePkcs8KeyDer, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rcgen::{CertificateParams, KeyPair};
use log::info;
use ::time::OffsetDateTime;

use serde::{Serialize, Deserialize};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use std::net::ToSocketAddrs;
use tokio::time;
use rand::seq::SliceRandom;
use rand::thread_rng;

use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::digest;
use aes::cipher::{KeyIvInit, StreamCipher};
type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

use tokio::sync::mpsc;
use std::collections::HashMap;
use tokio::sync::RwLock;

use governor::{Quota, RateLimiter};
use governor::state::direct::NotKeyed;
use governor::state::InMemoryState;
use governor::clock::QuantaClock;
use governor::middleware::NoOpMiddleware;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct Metrics {
    pub bytes_received: AtomicU64,
    pub active_connections: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            bytes_received: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }
}

pub async fn start_metrics_server(addr: &str, metrics: Arc<Metrics>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    info!("Metrics server listening on {}", addr);
    loop {
        if let Ok((mut socket, _)) = listener.accept().await {
            let m = metrics.clone();
            tokio::spawn(async move {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"bytes_received\": {}, \"active_connections\": {}}}",
                    m.bytes_received.load(Ordering::Relaxed),
                    m.active_connections.load(Ordering::Relaxed)
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    }
}

#[derive(Clone)]
pub struct BandwidthManager {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, QuantaClock, NoOpMiddleware>>,
}

impl BandwidthManager {
    pub fn new(bytes_per_sec: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(bytes_per_sec).unwrap_or(NonZeroU32::new(10 * 1024 * 1024).unwrap())); // Default 10MB/s
        let limiter = Arc::new(RateLimiter::direct(quota));
        BandwidthManager { limiter }
    }

    pub async fn check(&self, bytes: usize) {
        if let Some(nonzero) = NonZeroU32::new(bytes as u32) {
            let _ = self.limiter.until_n_ready(nonzero).await;
        }
    }
}

// --- Exit policy ---
//
// Controls whether this relay will dial out on behalf of a `Begin` (exit) cell.
// Rules are evaluated in order, first match wins; if nothing matches the
// connection is implicitly rejected. With no rules at all (the compiled-in
// default when no `--exit-policy` file is given), every destination is
// rejected, i.e. the node behaves as a relay-only (non-exit) node.
//
// File format (one rule per line, `#` starts a trailing comment):
//   accept <ip-or-cidr>:<port-or-*>
//   reject <ip-or-cidr>:<port-or-*>
// Examples:
//   reject 127.0.0.0/8:*
//   reject *:25
//   accept *:*

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction { Accept, Reject }

#[derive(Debug, Clone)]
struct ExitRule {
    action: PolicyAction,
    // None == wildcard `*` for the address.
    net: Option<(std::net::Ipv4Addr, u8)>,
    // None == wildcard `*` for the port.
    port: Option<u16>,
}

#[derive(Debug, Clone, Default)]
pub struct ExitPolicy {
    rules: Vec<ExitRule>,
}

fn ipv4_in_cidr(addr: std::net::Ipv4Addr, net: std::net::Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 { return true; }
    let prefix = prefix.min(32);
    let mask: u32 = if prefix == 32 { u32::MAX } else { !0u32 << (32 - prefix) };
    (u32::from(addr) & mask) == (u32::from(net) & mask)
}

impl ExitPolicy {
    /// The default, safe policy: reject every exit connection (relay-only node).
    pub fn reject_all() -> Self { ExitPolicy { rules: Vec::new() } }

    /// Parses a simple line-based policy file. Basic `*` wildcards and IPv4 CIDR
    /// notation are supported; this is intentionally not a full Tor-compatible parser.
    pub fn parse(text: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut rules = Vec::new();
        for (idx, raw_line) in text.lines().enumerate() {
            let lineno = idx + 1;
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() { continue; }

            let mut parts = line.split_whitespace();
            let action_str = parts.next().ok_or_else(|| format!("exit-policy line {}: missing action", lineno))?;
            let action = match action_str.to_ascii_lowercase().as_str() {
                "accept" => PolicyAction::Accept,
                "reject" => PolicyAction::Reject,
                other => return Err(format!("exit-policy line {}: unknown action '{}' (expected accept/reject)", lineno, other).into()),
            };

            let addr_port = parts.next().ok_or_else(|| format!("exit-policy line {}: missing <ip-or-cidr>:<port-or-*>", lineno))?;
            let (ip_part, port_part) = addr_port.rsplit_once(':')
                .ok_or_else(|| format!("exit-policy line {}: expected '<ip-or-cidr>:<port-or-*>', got '{}'", lineno, addr_port))?;

            let net = if ip_part == "*" {
                None
            } else if let Some((n, p)) = ip_part.split_once('/') {
                let prefix: u8 = p.parse().map_err(|_| format!("exit-policy line {}: bad CIDR prefix '{}'", lineno, p))?;
                let ipv4: std::net::Ipv4Addr = n.parse().map_err(|_| format!("exit-policy line {}: bad IPv4 address '{}'", lineno, n))?;
                Some((ipv4, prefix))
            } else {
                let ipv4: std::net::Ipv4Addr = ip_part.parse().map_err(|_| format!("exit-policy line {}: bad IPv4 address '{}'", lineno, ip_part))?;
                Some((ipv4, 32u8))
            };

            let port = if port_part == "*" {
                None
            } else {
                Some(port_part.parse::<u16>().map_err(|_| format!("exit-policy line {}: bad port '{}'", lineno, port_part))?)
            };

            rules.push(ExitRule { action, net, port });
        }
        Ok(ExitPolicy { rules })
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("failed to read exit policy file '{}': {}", path, e))?;
        let policy = Self::parse(&text)?;
        info!("Loaded exit policy from {} ({} rule(s))", path, policy.rules.len());
        Ok(policy)
    }

    /// Evaluates the policy against an IPv4 destination. Non-IPv4 destinations
    /// (and destinations this relay cannot resolve) are conservatively rejected
    /// since the simple CIDR matcher only understands IPv4.
    pub fn is_allowed(&self, target_ip: std::net::Ipv4Addr, target_port: u16) -> bool {
        for rule in &self.rules {
            let ip_match = match rule.net { None => true, Some((net, prefix)) => ipv4_in_cidr(target_ip, net, prefix) };
            let port_match = match rule.port { None => true, Some(p) => p == target_port };
            if ip_match && port_match {
                return rule.action == PolicyAction::Accept;
            }
        }
        false // implicit final reject
    }
}

// --- TLS identity pinning ---
//
// The network has no PKI/CA: nodes present self-signed certificates. Historically
// `create_client_config` trusted only certs chaining to the node's own self-signed
// cert (used as a "root"), which doesn't validate any *other* peer's cert at all in
// practice. We replace that with an explicit, honestly-documented scheme:
//
//   * `create_client_config()` builds a "trust on first use" config that accepts
//     any presented certificate. This is ONLY meant for genuinely first-contact /
//     bootstrap dials where we don't yet have a `RelayDescriptor` for the peer.
//     A MITM on that specific first connection is NOT detected by this layer.
//   * `create_pinned_client_config(expected_cert_der)` builds a config that pins
//     to one exact certificate (byte-for-byte). Use this once we have a peer's
//     `RelayDescriptor` (whose `tls_public_key` field carries their TLS cert DER,
//     itself covered by the descriptor's Ed25519 signature) so subsequent
//     connections to that peer are cryptographically bound to their known identity.
//
// `connect_to_peer` automatically prefers the pinned path when a `Directory` is
// supplied and a descriptor is known for the target address, falling back to
// accept-any (logged) for unknown peers.

/// Accepts any server certificate. Only for bootstrap/first-contact connections
/// where no relay identity is known yet -- see module docs above.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Pins to one exact certificate (DER bytes), tied to a specific relay identity
/// known via its `RelayDescriptor`. See module docs above.
#[derive(Debug)]
struct PinnedServerCert {
    expected_der: Vec<u8>,
}

impl ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected_der.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("TLS certificate does not match the pinned RelayDescriptor for this peer".into()))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &rustls::crypto::ring::default_provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Resolves a ".root" domain to an Ed25519 VerifyingKey.
pub fn resolve_root_domain(domain: &str) -> Result<VerifyingKey, Box<dyn Error + Send + Sync>> {
    if !domain.ends_with(".root") { return Err("Not a .root domain".into()); }
    let b32_part = domain.trim_end_matches(".root");
    let bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, b32_part)
        .ok_or("Invalid base32 encoding")?;
    let key = VerifyingKey::try_from(&bytes[..])
        .map_err(|e| format!("Invalid key: {}", e))?;
    Ok(key)
}

// --- SOCKS5 Constants ---
pub const SOCKS5_VERSION: u8 = 0x05;
pub const SOCKS5_AUTH_NONE: u8 = 0x00;
pub const SOCKS5_CMD_CONNECT: u8 = 0x01;
pub const SOCKS5_ADDR_IPV4: u8 = 0x01;
pub const SOCKS5_ADDR_DOMAIN: u8 = 0x03;

#[derive(Debug)]
pub struct Packet {
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn encapsulate(payload_data: Vec<u8>) -> Vec<u8> {
        let length = payload_data.len() as u32;
        let mut framed_data = length.to_be_bytes().to_vec();
        framed_data.extend_from_slice(&payload_data);
        framed_data
    }

    pub async fn decapsulate<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut length_bytes = [0u8; 4];
        reader.read_exact(&mut length_bytes).await?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        const MAX_PACKET_LEN: usize = 16 * 1024 * 1024; // 16MB sanity cap to avoid OOM on malformed input
        if length > MAX_PACKET_LEN {
            return Err(format!("Packet too large: {} bytes", length).into());
        }
        let mut payload = vec![0; length];
        reader.read_exact(&mut payload).await?;
        Ok(Packet { payload })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RelayDescriptor {
    pub id: VerifyingKey,
    pub external_address: SocketAddr,
    pub tls_public_key: Vec<u8>,
    pub last_updated: u64,
    pub signature: Signature,
}

impl RelayDescriptor {
    pub fn new(id: VerifyingKey, external_address: SocketAddr, tls_public_key: Vec<u8>, private_id_key: &SigningKey) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let last_updated = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let dummy_signature = Signature::try_from(&[0u8; 64][..]).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let mut descriptor = RelayDescriptor { id, external_address, tls_public_key, last_updated, signature: dummy_signature };
        descriptor.sign(private_id_key)?;
        Ok(descriptor)
    }

    pub fn sign(&mut self, private_id_key: &SigningKey) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut temp = self.clone();
        temp.signature = Signature::try_from(&[0u8; 64][..]).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let encoded = bincode::serialize(&temp)?;
        self.signature = private_id_key.sign(&encoded);
        Ok(())
    }

    pub fn verify(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut temp = self.clone();
        temp.signature = Signature::try_from(&[0u8; 64][..]).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let encoded = bincode::serialize(&temp)?;
        self.id.verify(&encoded, &self.signature).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HiddenServiceDescriptor {
    pub identity_key: VerifyingKey,
    pub introduction_points: Vec<SocketAddr>,
    pub signature: Signature,
}

impl HiddenServiceDescriptor {
    pub fn new(identity_key: VerifyingKey, introduction_points: Vec<SocketAddr>, private_id_key: &SigningKey) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let dummy_signature = Signature::try_from(&[0u8; 64][..]).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let mut descriptor = HiddenServiceDescriptor { identity_key, introduction_points, signature: dummy_signature };
        descriptor.sign(private_id_key)?;
        Ok(descriptor)
    }

    pub fn sign(&mut self, private_id_key: &SigningKey) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut temp = self.clone();
        temp.signature = Signature::try_from(&[0u8; 64][..]).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let encoded = bincode::serialize(&temp)?;
        self.signature = private_id_key.sign(&encoded);
        Ok(())
    }

    pub fn verify(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut temp = self.clone();
        temp.signature = Signature::try_from(&[0u8; 64][..]).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        let encoded = bincode::serialize(&temp)?;
        self.identity_key.verify(&encoded, &self.signature).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInfo {
    pub descriptor: RelayDescriptor,
    pub last_seen: u64,
}

impl PeerInfo {
    pub fn new(descriptor: RelayDescriptor) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let last_seen = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(PeerInfo { descriptor, last_seen })
    }
}

#[derive(Debug, Clone)]
pub struct PeerStore {
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
}

impl PeerStore {
    pub fn new() -> Self { PeerStore { peers: Arc::new(RwLock::new(HashMap::new())) } }
    pub async fn add_peer(&self, peer_info: PeerInfo) {
        let mut lock = self.peers.write().await;
        lock.insert(peer_info.descriptor.external_address, peer_info);
    }
    pub async fn get_all_peers(&self) -> Vec<PeerInfo> {
        let lock = self.peers.read().await;
        lock.values().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub struct Directory {
    relays: Arc<RwLock<HashMap<VerifyingKey, RelayDescriptor>>>,
    hidden_services: Arc<RwLock<HashMap<VerifyingKey, HiddenServiceDescriptor>>>,
}

impl Directory {
    pub fn new() -> Self { 
        Directory { 
            relays: Arc::new(RwLock::new(HashMap::new())),
            hidden_services: Arc::new(RwLock::new(HashMap::new())),
        } 
    }

    pub async fn add_relay(&self, descriptor: RelayDescriptor) -> bool {
        if descriptor.verify().is_err() { return false; }
        let mut write_guard = self.relays.write().await;
        if let Some(existing) = write_guard.get(&descriptor.id) {
            if descriptor.last_updated <= existing.last_updated { return false; }
        }
        write_guard.insert(descriptor.id.clone(), descriptor);
        true
    }
    
    pub async fn get_all_relays(&self) -> Vec<RelayDescriptor> {
        let lock = self.relays.read().await;
        lock.values().cloned().collect()
    }

    pub async fn publish_hidden_service(&self, descriptor: HiddenServiceDescriptor) -> bool {
        if descriptor.verify().is_err() {
            log::warn!("Rejected hidden service descriptor with invalid signature for {:?}", descriptor.identity_key);
            return false;
        }
        let mut lock = self.hidden_services.write().await;
        let key = descriptor.identity_key;
        lock.insert(key, descriptor);
        info!("Published hidden service descriptor for {:?}", key);
        true
    }

    pub async fn get_hidden_service(&self, key: &VerifyingKey) -> Option<HiddenServiceDescriptor> {
        let lock = self.hidden_services.read().await;
        lock.get(key).cloned()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message { Gossip(GossipMessage), TorCell(Cell) }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GossipMessage { Update(Vec<RelayDescriptor>) }

pub type CircuitId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CellCommand { Padding = 0, Create = 1, Created = 2, Relay = 3, Destroy = 4 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cell { pub circ_id: CircuitId, pub command: CellCommand, pub payload: Vec<u8> }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RelayCommand { 
    Begin = 1, 
    Data = 2, 
    End = 3, 
    Connected = 4, 
    SendMe = 5, 
    Extend = 6, 
    Extended = 7,
    Truncate = 8,
    Truncated = 9,
    Drop = 10,
    Resolve = 11,
    Resolved = 12,
    BeginDir = 13,
    Extend2 = 14,
    Extended2 = 15,
    EstablishIntro = 32,
    Introduce1 = 33,
    Introduce2 = 34,
    Rendezvous1 = 35,
    Rendezvous2 = 36,
    IntroEstablished = 37,
    EstablishRendezvous = 38,
    RendezvousEstablished = 39,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCell { pub stream_id: u16, pub recognized: u16, pub digest: u32, pub command: RelayCommand, pub data: Vec<u8> }

pub const STREAM_WINDOW_START: u16 = 500;
pub const STREAM_WINDOW_INCREMENT: u16 = 50;

#[derive(Debug)]
pub struct Stream {
    pub stream_id: u16,
    pub tcp_stream: Arc<tokio::sync::Mutex<TcpStream>>,
    pub package_window: u16,
    pub deliver_window: u16,
}

pub const CIRCUIT_WINDOW_START: u16 = 1000;
pub const CIRCUIT_WINDOW_INCREMENT: u16 = 100;

pub struct Circuit {
    pub id: CircuitId,
    pub next_hop: Option<SocketAddr>,
    pub next_hop_stream: Option<Arc<tokio::sync::Mutex<tokio_rustls::client::TlsStream<TcpStream>>>>,
    pub prev_hop: Option<SocketAddr>,
    pub prev_hop_stream: Option<Arc<tokio::sync::Mutex<tokio_rustls::server::TlsStream<TcpStream>>>>,
    pub forward_cipher: Option<Aes256Ctr>,
    pub backward_cipher: Option<Aes256Ctr>,
    pub streams: HashMap<u16, Stream>, 
    pub op_streams: HashMap<u16, mpsc::Sender<Vec<u8>>>,
    pub package_window: u16,
    pub deliver_window: u16,
    pub linked_circuit_id: Option<CircuitId>,
}

#[derive(Clone)]
pub struct CircuitManager {
    circuits: Arc<RwLock<HashMap<CircuitId, Arc<RwLock<Circuit>>>>>,
    pub intro_points: Arc<RwLock<HashMap<VerifyingKey, CircuitId>>>,
    pub rendezvous_points: Arc<RwLock<HashMap<[u8; 20], CircuitId>>>,
}

impl CircuitManager {
    pub fn new() -> Self { 
        CircuitManager { 
            circuits: Arc::new(RwLock::new(HashMap::new())),
            intro_points: Arc::new(RwLock::new(HashMap::new())),
            rendezvous_points: Arc::new(RwLock::new(HashMap::new())),
        } 
    }

    pub async fn add_circuit(&self, circuit: Circuit) {
        let mut lock = self.circuits.write().await;
        lock.insert(circuit.id, Arc::new(RwLock::new(circuit)));
    }
    pub async fn get_circuit(&self, id: CircuitId) -> Option<Arc<RwLock<Circuit>>> {
        let lock = self.circuits.read().await;
        lock.get(&id).cloned()
    }
}

async fn handle_extend(circuit: &mut Circuit, extend_payload: Vec<u8>, client_tls_config: Arc<ClientConfig>, directory: Arc<Directory>) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    if extend_payload.len() < 6 {
        return Err("Malformed EXTEND payload: too short".into());
    }
    let addr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(extend_payload[0], extend_payload[1], extend_payload[2], extend_payload[3])), u16::from_be_bytes([extend_payload[4], extend_payload[5]]));
    let create_payload = &extend_payload[6..];
    let mut next_stream = connect_to_peer(addr, client_tls_config, Some(&directory)).await?;
    let create_cell = Cell { circ_id: circuit.id, command: CellCommand::Create, payload: create_payload.to_vec() };
    next_stream.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(create_cell))?)).await?;
    let resp = Packet::decapsulate(&mut next_stream).await?;
    if let Message::TorCell(cell) = bincode::deserialize(&resp.payload)? {
        if cell.command == CellCommand::Created {
            circuit.next_hop = Some(addr);
            circuit.next_hop_stream = Some(Arc::new(tokio::sync::Mutex::new(next_stream)));
            return Ok(cell.payload);
        }
    }
    Err("Extend failed".into())
}

async fn handle_create_cell(cell: Cell, circuit_manager: Arc<CircuitManager>, stream_arc: Arc<tokio::sync::Mutex<tokio_rustls::server::TlsStream<TcpStream>>>) -> Result<Cell, Box<dyn Error + Send + Sync>> {
    let rng = ring::rand::SystemRandom::new();
    let priv_key = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| "Keygen fail")?;
    let pub_key = priv_key.compute_public_key().map_err(|_| "Keygen fail")?;
    let shared_secret = agreement::agree_ephemeral(priv_key, &UnparsedPublicKey::new(&X25519, &cell.payload), |m| {
        let hash = digest::digest(&digest::SHA256, m);
        let mut k = [0u8; 32]; k.copy_from_slice(hash.as_ref()); k
    }).map_err(|_| "Handshake fail")?;
    let circuit = Circuit {
        id: cell.circ_id,
        next_hop: None,
        next_hop_stream: None,
        prev_hop: None,
        prev_hop_stream: Some(stream_arc),
        forward_cipher: Some(Aes256Ctr::new(&shared_secret.into(), &[0u8; 16].into())),
        backward_cipher: Some(Aes256Ctr::new(&shared_secret.into(), &[0u8; 16].into())),
        streams: HashMap::new(),
        op_streams: HashMap::new(),
        package_window: CIRCUIT_WINDOW_START,
        deliver_window: CIRCUIT_WINDOW_START,
        linked_circuit_id: None,
    };
    circuit_manager.add_circuit(circuit).await;
    Ok(Cell { circ_id: cell.circ_id, command: CellCommand::Created, payload: pub_key.as_ref().to_vec() })
}

/// Loads a persistent Ed25519 signing key from `<data_dir>/identity.key`, generating
/// and saving a new one if it doesn't exist yet. Best-effort restricts file permissions
/// on Unix; on Windows this is a no-op (doesn't block startup).
pub fn load_or_create_signing_key(data_dir: &str) -> Result<SigningKey, Box<dyn Error + Send + Sync>> {
    std::fs::create_dir_all(data_dir)?;
    let key_path = std::path::Path::new(data_dir).join("identity.key");

    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        if bytes.len() != 32 {
            return Err(format!("Identity key file {} is corrupt (expected 32 bytes, got {})", key_path.display(), bytes.len()).into());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        info!("Loaded persistent identity from {}", key_path.display());
        return Ok(SigningKey::from_bytes(&key_bytes));
    }

    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    std::fs::write(&key_path, signing_key.to_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&key_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&key_path, perms);
        }
    }

    info!("Generated new persistent identity, saved to {}", key_path.display());
    Ok(signing_key)
}

pub fn init_logging() { env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init(); }

pub fn generate_self_signed_cert(hostname: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![hostname.to_string()]).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "Nebula TorPortal");
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + std::time::Duration::from_secs(365 * 24 * 60 * 60);
    let cert = params.self_signed(&key_pair).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
    Ok((cert.der().to_vec(), key_pair.serialize_der().to_vec()))
}

pub fn create_server_config(cert_der: Vec<u8>, pk_der: Vec<u8>) -> Result<Arc<ServerConfig>, Box<dyn Error + Send + Sync>> {
    let config = ServerConfig::builder().with_client_cert_verifier(WebPkiClientVerifier::no_client_auth()).with_single_cert(vec![CertificateDer::from(cert_der)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pk_der))).map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
    Ok(Arc::new(config))
}

/// Builds a "trust on first use" client TLS config that accepts any presented
/// certificate. This is intentionally permissive and should only be used for
/// genuinely first-contact/bootstrap dials where no `RelayDescriptor` is known
/// yet for the peer -- see the TLS identity pinning docs above `AcceptAnyServerCert`.
/// A MITM on such a first connection is NOT detected by this layer.
pub fn create_client_config() -> Result<Arc<ClientConfig>, Box<dyn Error + Send + Sync>> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Builds a client TLS config pinned to one exact certificate (DER bytes),
/// normally sourced from a peer's `RelayDescriptor.tls_public_key` (itself
/// covered by that descriptor's Ed25519 signature). Connections made with this
/// config will fail unless the peer presents exactly this certificate.
pub fn create_pinned_client_config(expected_cert_der: Vec<u8>) -> Result<Arc<ClientConfig>, Box<dyn Error + Send + Sync>> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCert { expected_der: expected_cert_der }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub async fn listen_for_connections(addr: &str, server_config: Arc<ServerConfig>, directory: Arc<Directory>, circuit_manager: Arc<CircuitManager>, client_tls_config: Arc<ClientConfig>, bw_manager: Arc<BandwidthManager>, metrics: Arc<Metrics>, exit_policy: Arc<ExitPolicy>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    info!("Relay listening on {}", addr);
    let tls_acceptor = TlsAcceptor::from(server_config);
    loop {
        let (socket, _peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let dir = directory.clone();
        let cm = circuit_manager.clone();
        let cc = client_tls_config.clone();
        let bw = bw_manager.clone();
        let m = metrics.clone();
        let ep = exit_policy.clone();
        tokio::spawn(async move {
            if let Ok(tls_stream) = acceptor.accept(socket).await {
                handle_incoming_connection(tls_stream, dir, cm, cc, bw, m, ep).await;
            }
        });
    }
}

pub async fn connect_to_relay(addr: &str, client_config: Arc<ClientConfig>) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn Error + Send + Sync>> {
    let socket = TcpStream::connect(addr).await?;
    let host = addr.split(':').next().unwrap();
    let server_name = if let Ok(ip) = host.parse::<std::net::IpAddr>() { ServerName::IpAddress(ip.into()) } else { ServerName::try_from(host).map_err(|e| format!("{:?}", e))?.to_owned() };
    Ok(TlsConnector::from(client_config).connect(server_name, socket).await?)
}

/// Connects to a peer, pinning the TLS connection to their known identity when
/// possible. If `directory` is provided and contains a `RelayDescriptor` for
/// `peer_addr` with a non-empty `tls_public_key`, the connection is pinned to
/// that exact certificate. Otherwise this falls back to `fallback_client_config`
/// (normally an accept-any/TOFU config from `create_client_config`) and logs the
/// gap -- this covers genuinely first-contact/bootstrap dials only.
pub async fn connect_to_peer(peer_addr: SocketAddr, fallback_client_config: Arc<ClientConfig>, directory: Option<&Arc<Directory>>) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn Error + Send + Sync>> {
    if let Some(dir) = directory {
        let known = dir.get_all_relays().await.into_iter()
            .find(|r| r.external_address == peer_addr && !r.tls_public_key.is_empty());
        if let Some(relay) = known {
            match create_pinned_client_config(relay.tls_public_key.clone()) {
                Ok(pinned_cfg) => return connect_to_relay(&peer_addr.to_string(), pinned_cfg).await,
                Err(e) => log::warn!("TLS: failed to build pinned config for {}: {}, falling back to unpinned", peer_addr, e),
            }
        }
    }
    log::warn!("TLS: no pinned RelayDescriptor known for {}, connecting with accept-any TOFU trust (bootstrap gap)", peer_addr);
    connect_to_relay(&peer_addr.to_string(), fallback_client_config).await
}

async fn handle_incoming_connection(tls_stream: tokio_rustls::server::TlsStream<TcpStream>, directory: Arc<Directory>, circuit_manager: Arc<CircuitManager>, client_tls_config: Arc<ClientConfig>, bw_manager: Arc<BandwidthManager>, metrics: Arc<Metrics>, exit_policy: Arc<ExitPolicy>) {
    metrics.active_connections.fetch_add(1, Ordering::Relaxed);
    let stream_arc = Arc::new(tokio::sync::Mutex::new(tls_stream));
    loop {
        let packet = {
            let mut lock = stream_arc.lock().await;
            match Packet::decapsulate(&mut *lock).await { Ok(p) => p, Err(_) => break }
        };
        
        metrics.bytes_received.fetch_add((packet.payload.len() + 4) as u64, Ordering::Relaxed);
        bw_manager.check(packet.payload.len() + 4).await; // 4 bytes header
        
        if let Ok(message) = bincode::deserialize::<Message>(&packet.payload) {
            match message {
                Message::Gossip(GossipMessage::Update(descriptors)) => {
                    for d in descriptors { directory.add_relay(d).await; }
                    // Reply with our own view of the directory so gossip propagates both ways.
                    let reply = Message::Gossip(GossipMessage::Update(directory.get_all_relays().await));
                    if let Ok(encoded) = bincode::serialize(&reply) {
                        let mut lock = stream_arc.lock().await;
                        let _ = lock.write_all(&Packet::encapsulate(encoded)).await;
                    }
                }
                Message::TorCell(mut cell) => {
                    match cell.command {
                        CellCommand::Create => { 
                            if let Ok(resp) = handle_create_cell(cell, circuit_manager.clone(), stream_arc.clone()).await { 
                                let mut lock = stream_arc.lock().await;
                                let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(resp)).unwrap())).await; 
                            } 
                        }
                        CellCommand::Relay => {
                            if let Some(cm_lock) = circuit_manager.get_circuit(cell.circ_id).await {
                                let mut circuit = cm_lock.write().await;
                                if let Some(ref mut cipher) = circuit.forward_cipher {
                                    cipher.apply_keystream(&mut cell.payload);
                                    if let Ok(relay_cell) = bincode::deserialize::<RelayCell>(&cell.payload) {
                                        if relay_cell.recognized == 0 {
                                            // If this circuit has been linked to another one via a
                                            // completed rendezvous (see RelayCommand::Rendezvous1
                                            // below), this relay is acting as the rendezvous point:
                                            // bridge everything except the rendezvous-setup cells
                                            // themselves straight through to the linked circuit
                                            // instead of interpreting it locally.
                                            if let Some(linked_id) = circuit.linked_circuit_id {
                                                if !matches!(relay_cell.command, RelayCommand::EstablishRendezvous | RelayCommand::Rendezvous1) {
                                                    if let Some(linked_lock) = circuit_manager.get_circuit(linked_id).await {
                                                        let mut linked_circ = linked_lock.write().await;
                                                        let target_stream_opt = linked_circ.prev_hop_stream.clone();
                                                        if let Some(target_stream) = target_stream_opt {
                                                            let mut p = bincode::serialize(&relay_cell).unwrap();
                                                            if let Some(ref mut bc) = linked_circ.backward_cipher { bc.apply_keystream(&mut p); }
                                                            let cell_out = Cell { circ_id: linked_id, command: CellCommand::Relay, payload: p };
                                                            let packet = Packet::encapsulate(bincode::serialize(&Message::TorCell(cell_out)).unwrap());
                                                            let mut lock = target_stream.lock().await;
                                                            let _ = lock.write_all(&packet).await;
                                                        }
                                                    }
                                                    continue;
                                                }
                                            }
                                            match relay_cell.command {
                                                RelayCommand::Extend => {
                                                    if let Ok(data) = handle_extend(&mut circuit, relay_cell.data, client_tls_config.clone(), directory.clone()).await {
                                                        let mut p = bincode::serialize(&RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::Extended, data }).unwrap();
                                                        if let Some(ref mut bc) = circuit.backward_cipher { bc.apply_keystream(&mut p); }
                                                        let mut lock = stream_arc.lock().await;
                                                        let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(Cell { circ_id: cell.circ_id, command: CellCommand::Relay, payload: p })).unwrap())).await;
                                                    }
                                                }
                                                RelayCommand::Begin => {
                                                    let addr_str = String::from_utf8_lossy(&relay_cell.data).to_string();

                                                    // Resolve the requested destination and check it against this
                                                    // relay's exit policy *before* dialing out. Non-IPv4 results are
                                                    // conservatively rejected (the policy matcher only understands IPv4).
                                                    let resolved_v4: Option<std::net::SocketAddrV4> = match tokio::net::lookup_host(addr_str.as_str()).await {
                                                        Ok(mut addrs) => addrs.find_map(|a| match a { SocketAddr::V4(v4) => Some(v4), SocketAddr::V6(_) => None }),
                                                        Err(_) => None,
                                                    };
                                                    let allowed = resolved_v4.map(|v4| exit_policy.is_allowed(*v4.ip(), v4.port())).unwrap_or(false);

                                                    if !allowed {
                                                        log::warn!("Exit policy rejected Begin to '{}' on circuit {}", addr_str, cell.circ_id);
                                                        let mut p = bincode::serialize(&RelayCell { stream_id: relay_cell.stream_id, recognized: 0, digest: 0, command: RelayCommand::End, data: b"exit policy rejected".to_vec() }).unwrap();
                                                        if let Some(ref mut bc) = circuit.backward_cipher { bc.apply_keystream(&mut p); }
                                                        let mut lock = stream_arc.lock().await;
                                                        let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(Cell { circ_id: cell.circ_id, command: CellCommand::Relay, payload: p })).unwrap())).await;
                                                    } else if let Ok(target) = TcpStream::connect(addr_str.as_str()).await {
                                                        let target_arc = Arc::new(tokio::sync::Mutex::new(target));
                                                        let stream = Stream {
                                                            stream_id: relay_cell.stream_id,
                                                            tcp_stream: target_arc.clone(),
                                                            package_window: STREAM_WINDOW_START,
                                                            deliver_window: STREAM_WINDOW_START,
                                                        };
                                                        circuit.streams.insert(relay_cell.stream_id, stream);
                                                        let mut p = bincode::serialize(&RelayCell { stream_id: relay_cell.stream_id, recognized: 0, digest: 0, command: RelayCommand::Connected, data: vec![] }).unwrap();
                                                        if let Some(ref mut bc) = circuit.backward_cipher { bc.apply_keystream(&mut p); }
                                                        let mut lock = stream_arc.lock().await;
                                                        let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(Cell { circ_id: cell.circ_id, command: CellCommand::Relay, payload: p })).unwrap())).await;
                                                    } else {
                                                        let mut p = bincode::serialize(&RelayCell { stream_id: relay_cell.stream_id, recognized: 0, digest: 0, command: RelayCommand::End, data: b"connect failed".to_vec() }).unwrap();
                                                        if let Some(ref mut bc) = circuit.backward_cipher { bc.apply_keystream(&mut p); }
                                                        let mut lock = stream_arc.lock().await;
                                                        let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(Cell { circ_id: cell.circ_id, command: CellCommand::Relay, payload: p })).unwrap())).await;
                                                    }
                                                }
                                                RelayCommand::Data => {
                                                    circuit.deliver_window -= 1;
                                                    if circuit.deliver_window <= CIRCUIT_WINDOW_START - CIRCUIT_WINDOW_INCREMENT {
                                                        let sendme = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::SendMe, data: vec![] };
                                                        let mut p = bincode::serialize(&sendme).unwrap();
                                                        if let Some(ref mut bc) = circuit.backward_cipher { bc.apply_keystream(&mut p); }
                                                        let mut lock = stream_arc.lock().await;
                                                        let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(Cell { circ_id: cell.circ_id, command: CellCommand::Relay, payload: p })).unwrap())).await;
                                                        circuit.deliver_window += CIRCUIT_WINDOW_INCREMENT;
                                                    }
                                                    let mut send_stream_sendme = false;
                                                    if let Some(s) = circuit.streams.get_mut(&relay_cell.stream_id) {
                                                        s.deliver_window -= 1;
                                                        if s.deliver_window <= STREAM_WINDOW_START - STREAM_WINDOW_INCREMENT {
                                                            send_stream_sendme = true;
                                                            s.deliver_window += STREAM_WINDOW_INCREMENT;
                                                        }
                                                        let _ = s.tcp_stream.lock().await.write_all(&relay_cell.data).await;
                                                    }
                                                    if send_stream_sendme {
                                                        let sendme = RelayCell { stream_id: relay_cell.stream_id, recognized: 0, digest: 0, command: RelayCommand::SendMe, data: vec![] };
                                                        let mut p = bincode::serialize(&sendme).unwrap();
                                                        if let Some(ref mut bc) = circuit.backward_cipher { bc.apply_keystream(&mut p); }
                                                        let mut lock = stream_arc.lock().await;
                                                        let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(Cell { circ_id: cell.circ_id, command: CellCommand::Relay, payload: p })).unwrap())).await;
                                                    }
                                                }
                                                RelayCommand::SendMe => {
                                                    if relay_cell.stream_id == 0 {
                                                        circuit.package_window += CIRCUIT_WINDOW_INCREMENT;
                                                    } else if let Some(s) = circuit.streams.get_mut(&relay_cell.stream_id) {
                                                        s.package_window += STREAM_WINDOW_INCREMENT;
                                                    }
                                                }
                                                RelayCommand::End => {
                                                    if let Some(_) = circuit.streams.remove(&relay_cell.stream_id) {
                                                        info!("Stream {} closed.", relay_cell.stream_id);
                                                    }
                                                }
                                                RelayCommand::EstablishIntro => {
                                                    if relay_cell.data.len() >= 32 {
                                                        let key_bytes: Result<[u8; 32], _> = relay_cell.data[0..32].try_into();
                                                        let Ok(key_bytes) = key_bytes else {
                                                            log::warn!("Malformed ESTABLISH_INTRO key length, dropping cell");
                                                            continue;
                                                        };
                                                        if let Ok(key) = VerifyingKey::from_bytes(&key_bytes) {
                                                            circuit_manager.intro_points.write().await.insert(key, cell.circ_id);
                                                            info!("Registered Introduction Point for service {:?}", key);
                                                            let intro_est = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::IntroEstablished, data: vec![] };
                                                            let mut p = bincode::serialize(&intro_est).unwrap();
                                                            if let Some(ref mut bc) = circuit.backward_cipher { bc.apply_keystream(&mut p); }
                                                            let mut lock = stream_arc.lock().await;
                                                            let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(Cell { circ_id: cell.circ_id, command: CellCommand::Relay, payload: p })).unwrap())).await;
                                                        }
                                                    }
                                                }
                                                RelayCommand::Introduce1 => {
                                                    if relay_cell.data.len() >= 32 {
                                                        let key_bytes: Result<[u8; 32], _> = relay_cell.data[0..32].try_into();
                                                        let Ok(key_bytes) = key_bytes else {
                                                            log::warn!("Malformed INTRODUCE1 key length, dropping cell");
                                                            continue;
                                                        };
                                                        if let Ok(key) = VerifyingKey::from_bytes(&key_bytes) {
                                                            if let Some(service_circ_id) = circuit_manager.intro_points.read().await.get(&key) {
                                                                if let Some(service_circ_lock) = circuit_manager.get_circuit(*service_circ_id).await {
                                                                    let mut service_circ = service_circ_lock.write().await;
                                                                    let target_stream_opt = service_circ.prev_hop_stream.clone();
                                                                    if let Some(target_stream) = target_stream_opt {
                                                                        let intro2 = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::Introduce2, data: relay_cell.data.clone() };
                                                                        let mut p = bincode::serialize(&intro2).unwrap();
                                                                        if let Some(ref mut bc) = service_circ.backward_cipher { bc.apply_keystream(&mut p); }
                                                                        let cell_out = Cell { circ_id: *service_circ_id, command: CellCommand::Relay, payload: p };
                                                                        let packet = Packet::encapsulate(bincode::serialize(&Message::TorCell(cell_out)).unwrap());
                                                                        let mut lock = target_stream.lock().await;
                                                                        let _ = lock.write_all(&packet).await;
                                                                        info!("Forwarded INTRODUCE2 to service");
                                                                    }
                                                                }
                                                            } else { info!("Service not found for INTRODUCE1"); }
                                                        }
                                                    }
                                                }
                                                RelayCommand::EstablishRendezvous => {
                                                    if relay_cell.data.len() == 20 {
                                                        let cookie_bytes: Result<[u8; 20], _> = relay_cell.data.clone().try_into();
                                                        let Ok(cookie) = cookie_bytes else {
                                                            log::warn!("Malformed ESTABLISH_RENDEZVOUS cookie length, dropping cell");
                                                            continue;
                                                        };
                                                        circuit_manager.rendezvous_points.write().await.insert(cookie, cell.circ_id);
                                                        info!("Registered Rendezvous Point with cookie {:?}", cookie);
                                                        let est = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::RendezvousEstablished, data: vec![] };
                                                        let mut p = bincode::serialize(&est).unwrap();
                                                        if let Some(ref mut bc) = circuit.backward_cipher { bc.apply_keystream(&mut p); }
                                                        let mut lock = stream_arc.lock().await;
                                                        let _ = lock.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(Cell { circ_id: cell.circ_id, command: CellCommand::Relay, payload: p })).unwrap())).await;
                                                    }
                                                }
                                                RelayCommand::Rendezvous1 => {
                                                    if relay_cell.data.len() >= 20 {
                                                        let cookie_bytes: Result<[u8; 20], _> = relay_cell.data[0..20].try_into();
                                                        let Ok(cookie) = cookie_bytes else {
                                                            log::warn!("Malformed RENDEZVOUS1 cookie length, dropping cell");
                                                            continue;
                                                        };
                                                        if let Some(client_circ_id) = circuit_manager.rendezvous_points.read().await.get(&cookie) {
                                                            circuit.linked_circuit_id = Some(*client_circ_id);
                                                            if let Some(client_circ_lock) = circuit_manager.get_circuit(*client_circ_id).await {
                                                                let mut client_circ = client_circ_lock.write().await;
                                                                client_circ.linked_circuit_id = Some(cell.circ_id);
                                                                let target_stream_opt = client_circ.prev_hop_stream.clone();
                                                                if let Some(target_stream) = target_stream_opt {
                                                                    let rend2 = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::Rendezvous2, data: relay_cell.data[20..].to_vec() };
                                                                    let mut p = bincode::serialize(&rend2).unwrap();
                                                                    if let Some(ref mut bc) = client_circ.backward_cipher { bc.apply_keystream(&mut p); }
                                                                    let cell_out = Cell { circ_id: *client_circ_id, command: CellCommand::Relay, payload: p };
                                                                    let packet = Packet::encapsulate(bincode::serialize(&Message::TorCell(cell_out)).unwrap());
                                                                    let mut lock = target_stream.lock().await;
                                                                    let _ = lock.write_all(&packet).await;
                                                                    info!("Forwarded RENDEZVOUS2 to client");
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => info!("Command {:?} unimplemented locally", relay_cell.command),
                                            }
                                        } else if let Some(ref ns) = circuit.next_hop_stream {
                                            let ns_clone = ns.clone();
                                            let p = Packet::encapsulate(bincode::serialize(&Message::TorCell(cell)).unwrap());
                                            tokio::spawn(async move { let _ = ns_clone.lock().await.write_all(&p).await; });
                                        }
                                    }
                                }
                            }
                        }
                        CellCommand::Padding => {}
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Encrypts a RelayCell with the circuit's forward cipher and sends it out on `stream`
/// wrapped in a TorCell::Relay.
async fn send_relay_cell(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    circ_id: CircuitId,
    forward_cipher: &mut Aes256Ctr,
    relay_cell: &RelayCell,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut payload = bincode::serialize(relay_cell)?;
    forward_cipher.apply_keystream(&mut payload);
    let cell = Cell { circ_id, command: CellCommand::Relay, payload };
    stream.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(cell))?)).await?;
    Ok(())
}

/// Reads one TorCell::Relay from `stream`, decrypts it with the backward cipher, and
/// returns the decoded RelayCell.
async fn recv_relay_cell(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    backward_cipher: &mut Aes256Ctr,
) -> Result<RelayCell, Box<dyn Error + Send + Sync>> {
    let packet = Packet::decapsulate(stream).await?;
    let message: Message = bincode::deserialize(&packet.payload)?;
    if let Message::TorCell(mut cell) = message {
        if cell.command == CellCommand::Relay {
            backward_cipher.apply_keystream(&mut cell.payload);
            let relay_cell: RelayCell = bincode::deserialize(&cell.payload)?;
            return Ok(relay_cell);
        }
    }
    Err("Expected relay cell".into())
}

pub async fn start_socks_proxy(listen_addr: &str, directory: Arc<Directory>, _circuit_manager: Arc<CircuitManager>, client_config: Arc<ClientConfig>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!("SOCKS5 proxy listening on {}", listen_addr);
    loop {
        let (mut socket, _) = listener.accept().await?;
        let dir = directory.clone();
        let cc = client_config.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2];
            if socket.read_exact(&mut buf).await.is_ok() && buf[0] == SOCKS5_VERSION {
                let mut methods = vec![0u8; buf[1] as usize];
                let _ = socket.read_exact(&mut methods).await;
                let _ = socket.write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE]).await;
                let mut req = [0u8; 4];
                if socket.read_exact(&mut req).await.is_ok() && req[1] == SOCKS5_CMD_CONNECT {
                    let mut addr_buf = [0u8; 1];
                    let _ = socket.read_exact(&mut addr_buf).await;
                    let target = if addr_buf[0] == SOCKS5_ADDR_IPV4 {
                        let mut ip = [0u8; 4]; let _ = socket.read_exact(&mut ip).await;
                        let mut port = [0u8; 2]; let _ = socket.read_exact(&mut port).await;
                        format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], u16::from_be_bytes(port))
                    } else if addr_buf[0] == SOCKS5_ADDR_DOMAIN {
                        let mut len = [0u8; 1]; let _ = socket.read_exact(&mut len).await;
                        let mut domain = vec![0u8; len[0] as usize]; let _ = socket.read_exact(&mut domain).await;
                        let mut port = [0u8; 2]; let _ = socket.read_exact(&mut port).await;
                        format!("{}:{}", String::from_utf8_lossy(&domain), u16::from_be_bytes(port))
                    } else {
                        let _ = socket.write_all(&[SOCKS5_VERSION, 0x08, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                        return;
                    };
                    info!("SOCKS5: CONNECT to {}", target);

                    if target.ends_with(".root") {
                        let domain = target.split(':').next().unwrap_or("");
                        let key = match resolve_root_domain(domain) {
                            Ok(k) => k,
                            Err(e) => {
                                log::warn!("SOCKS5: failed to resolve .root domain {}: {}", domain, e);
                                let _ = socket.write_all(&[SOCKS5_VERSION, 0x04, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                return;
                            }
                        };

                        let hs_descriptor = match dir.get_hidden_service(&key).await {
                            Some(d) => d,
                            None => {
                                log::warn!("SOCKS5: no hidden-service descriptor known for {}", domain);
                                let _ = socket.write_all(&[SOCKS5_VERSION, 0x04, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                return;
                            }
                        };
                        if hs_descriptor.introduction_points.is_empty() {
                            log::warn!("SOCKS5: descriptor for {} has no introduction points", domain);
                            let _ = socket.write_all(&[SOCKS5_VERSION, 0x04, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                            return;
                        }

                        // --- Step 1: build a circuit to a rendezvous point (RP). ---
                        // Pick a random relay from the directory as the RP, and (when available)
                        // up to two more random relays as guard/middle hops in front of it, so
                        // the RP circuit is a normal multi-hop circuit like any other.
                        let mut rp_relays = dir.get_all_relays().await;
                        { let mut rng = thread_rng(); rp_relays.shuffle(&mut rng); }
                        if rp_relays.is_empty() {
                            log::warn!("SOCKS5: no relays known in directory, cannot pick a rendezvous point");
                            let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                            return;
                        }
                        let rp_addr = rp_relays[0].external_address;
                        let mut rp_path: Vec<SocketAddr> = rp_relays.iter().skip(1).take(2).map(|r| r.external_address).collect();
                        rp_path.push(rp_addr);

                        let rp_circ_id: CircuitId = rand::random();
                        let (rp_circuit_arc, mut rp_stream) = match establish_circuit(rp_circ_id, rp_path, cc.clone(), dir.clone()).await {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("SOCKS5: failed to build circuit to rendezvous point {}: {}", rp_addr, e);
                                let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                return;
                            }
                        };
                        let (mut rp_fwd, mut rp_bwd) = {
                            let c = rp_circuit_arc.read().await;
                            match (c.forward_cipher.clone(), c.backward_cipher.clone()) {
                                (Some(f), Some(b)) => (f, b),
                                _ => {
                                    let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                    return;
                                }
                            }
                        };

                        // --- Step 2: establish the rendezvous point with a fresh cookie. ---
                        let cookie: [u8; 20] = rand::random();
                        let est_rend = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::EstablishRendezvous, data: cookie.to_vec() };
                        if send_relay_cell(&mut rp_stream, rp_circ_id, &mut rp_fwd, &est_rend).await.is_err() {
                            log::warn!("SOCKS5: failed to send ESTABLISH_RENDEZVOUS to {}", rp_addr);
                            let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                            return;
                        }
                        match recv_relay_cell(&mut rp_stream, &mut rp_bwd).await {
                            Ok(rc) if rc.command == RelayCommand::RendezvousEstablished => {}
                            _ => {
                                log::warn!("SOCKS5: rendezvous point {} did not confirm establishment", rp_addr);
                                let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                return;
                            }
                        }

                        // --- Step 3/4: build a circuit to one of the HS's introduction points
                        // and send INTRODUCE1 carrying the service key, RP address, and cookie. ---
                        let mut intro_points = hs_descriptor.introduction_points.clone();
                        { let mut rng = thread_rng(); intro_points.shuffle(&mut rng); }
                        let intro_addr = intro_points[0];
                        let intro_circ_id: CircuitId = rand::random();
                        let (intro_circuit_arc, mut intro_stream) = match establish_circuit(intro_circ_id, vec![intro_addr], cc.clone(), dir.clone()).await {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("SOCKS5: failed to build circuit to intro point {}: {}", intro_addr, e);
                                let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                return;
                            }
                        };
                        let mut intro_fwd = {
                            let c = intro_circuit_arc.read().await;
                            match c.forward_cipher.clone() {
                                Some(f) => f,
                                None => {
                                    let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                    return;
                                }
                            }
                        };

                        let rp_ipv4 = match rp_addr.ip() {
                            std::net::IpAddr::V4(v4) => v4,
                            std::net::IpAddr::V6(_) => {
                                log::warn!("SOCKS5: IPv6 rendezvous points are not supported");
                                let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                return;
                            }
                        };
                        // Layout matches what the relay's INTRODUCE1 handler expects and
                        // forwards verbatim as INTRODUCE2: [service_key(32)][rp_ip(4)][rp_port(2)][cookie(20)]
                        let mut intro1_data = key.as_bytes().to_vec();
                        intro1_data.extend_from_slice(&rp_ipv4.octets());
                        intro1_data.extend_from_slice(&rp_addr.port().to_be_bytes());
                        intro1_data.extend_from_slice(&cookie);

                        let intro1 = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::Introduce1, data: intro1_data };
                        if send_relay_cell(&mut intro_stream, intro_circ_id, &mut intro_fwd, &intro1).await.is_err() {
                            log::warn!("SOCKS5: failed to send INTRODUCE1 to {}", intro_addr);
                            let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                            return;
                        }
                        // There is no acknowledgement cell defined for INTRODUCE1 on this
                        // circuit; the intro-point circuit is not needed after delivery.
                        drop(intro_stream);

                        // --- Step 5: wait for RENDEZVOUS2 on the RP circuit. ---
                        match time::timeout(time::Duration::from_secs(30), recv_relay_cell(&mut rp_stream, &mut rp_bwd)).await {
                            Ok(Ok(rc)) if rc.command == RelayCommand::Rendezvous2 => {
                                info!("SOCKS5: rendezvous with {} completed via {}", domain, rp_addr);
                            }
                            _ => {
                                log::warn!("SOCKS5: rendezvous with {} did not complete in time", domain);
                                let _ = socket.write_all(&[SOCKS5_VERSION, 0x04, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                return;
                            }
                        }

                        // --- Step 6: relay bytes bidirectionally between the SOCKS client and
                        // the rendezvous circuit. NOTE: the hidden-service side (handle_introduce2)
                        // does not implement a BEGIN/CONNECTED handshake on the rendezvous circuit
                        // -- it starts forwarding RelayCommand::Data cells to/from its fixed local
                        // target_addr immediately once RENDEZVOUS1 is sent. So the client must not
                        // send BEGIN here (the HS side would never see/ack it); we go straight to
                        // the data-relay loop, mirroring the non-.root path below minus the
                        // BEGIN/CONNECTED exchange. This means the requested destination port in
                        // `target` is NOT honored for .root addresses -- the HS operator's
                        // configured target_addr decides what the client actually reaches.
                        if socket.write_all(&[SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await.is_err() {
                            return;
                        }

                        let (mut client_rd, mut client_wr) = socket.into_split();
                        let (relay_rd, relay_wr) = tokio::io::split(rp_stream);
                        let relay_rd = Arc::new(tokio::sync::Mutex::new(relay_rd));
                        let relay_wr = Arc::new(tokio::sync::Mutex::new(relay_wr));

                        let up_fwd_cipher = Arc::new(tokio::sync::Mutex::new(rp_fwd));
                        let down_bwd_cipher = Arc::new(tokio::sync::Mutex::new(rp_bwd));

                        let up_relay_wr = relay_wr.clone();
                        let up_cipher = up_fwd_cipher.clone();
                        let upload = tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            loop {
                                let n = match client_rd.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => n };
                                let data_cell = RelayCell { stream_id: 1, recognized: 0, digest: 0, command: RelayCommand::Data, data: buf[..n].to_vec() };
                                let Ok(mut payload) = bincode::serialize(&data_cell) else { break };
                                { let mut c = up_cipher.lock().await; c.apply_keystream(&mut payload); }
                                let cell = Cell { circ_id: rp_circ_id, command: CellCommand::Relay, payload };
                                let Ok(encoded) = bincode::serialize(&Message::TorCell(cell)) else { break };
                                let mut wr = up_relay_wr.lock().await;
                                if wr.write_all(&Packet::encapsulate(encoded)).await.is_err() { break; }
                            }
                            let mut wr = up_relay_wr.lock().await;
                            let _ = wr.shutdown().await;
                        });

                        let down_relay_rd = relay_rd.clone();
                        let down_cipher = down_bwd_cipher.clone();
                        let download = tokio::spawn(async move {
                            loop {
                                let mut rd = down_relay_rd.lock().await;
                                let packet = match Packet::decapsulate(&mut *rd).await { Ok(p) => p, Err(_) => break };
                                drop(rd);
                                let Ok(Message::TorCell(mut cell)) = bincode::deserialize::<Message>(&packet.payload) else { continue };
                                if cell.command != CellCommand::Relay { continue; }
                                { let mut c = down_cipher.lock().await; c.apply_keystream(&mut cell.payload); }
                                let Ok(relay_cell) = bincode::deserialize::<RelayCell>(&cell.payload) else { continue };
                                match relay_cell.command {
                                    RelayCommand::Data => { if client_wr.write_all(&relay_cell.data).await.is_err() { break; } }
                                    RelayCommand::End => break,
                                    _ => {}
                                }
                            }
                            let _ = client_wr.shutdown().await;
                        });

                        let _ = tokio::join!(upload, download);
                        return;
                    }

                    // Pick up to 3 distinct relays from the directory to build a circuit.
                    let mut relays = dir.get_all_relays().await;
                    { let mut rng = thread_rng(); relays.shuffle(&mut rng); }
                    let path: Vec<SocketAddr> = relays.iter().take(3).map(|r| r.external_address).collect();
                    if path.is_empty() {
                        log::warn!("SOCKS5: no relays known in directory, cannot build circuit");
                        let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                        return;
                    }

                    let circ_id: CircuitId = rand::random();
                    let (circuit_arc, mut relay_stream) = match establish_circuit(circ_id, path, cc.clone(), dir.clone()).await {
                        Ok(v) => v,
                        Err(e) => {
                            log::warn!("SOCKS5: failed to establish circuit: {}", e);
                            let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                            return;
                        }
                    };

                    let (mut forward_cipher, mut backward_cipher) = {
                        let circuit = circuit_arc.read().await;
                        match (circuit.forward_cipher.clone(), circuit.backward_cipher.clone()) {
                            (Some(f), Some(b)) => (f, b),
                            _ => {
                                let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                                return;
                            }
                        }
                    };

                    let begin_cell = RelayCell { stream_id: 1, recognized: 0, digest: 0, command: RelayCommand::Begin, data: target.clone().into_bytes() };
                    if send_relay_cell(&mut relay_stream, circ_id, &mut forward_cipher, &begin_cell).await.is_err() {
                        let _ = socket.write_all(&[SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                        return;
                    }

                    match recv_relay_cell(&mut relay_stream, &mut backward_cipher).await {
                        Ok(rc) if rc.command == RelayCommand::Connected => {}
                        _ => {
                            log::warn!("SOCKS5: circuit did not connect to {}", target);
                            let _ = socket.write_all(&[SOCKS5_VERSION, 0x05, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await;
                            return;
                        }
                    }

                    // Success reply to the SOCKS5 client.
                    if socket.write_all(&[SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ADDR_IPV4, 0,0,0,0, 0,0]).await.is_err() {
                        return;
                    }

                    // Relay bytes bidirectionally between the client socket and the circuit
                    // until either side closes.
                    let (mut client_rd, mut client_wr) = socket.into_split();
                    let (relay_rd, relay_wr) = tokio::io::split(relay_stream);
                    let relay_rd = Arc::new(tokio::sync::Mutex::new(relay_rd));
                    let relay_wr = Arc::new(tokio::sync::Mutex::new(relay_wr));

                    let up_fwd_cipher = Arc::new(tokio::sync::Mutex::new(forward_cipher));
                    let down_bwd_cipher = Arc::new(tokio::sync::Mutex::new(backward_cipher));

                    let up_relay_wr = relay_wr.clone();
                    let up_cipher = up_fwd_cipher.clone();
                    let upload = tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        loop {
                            let n = match client_rd.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => n };
                            let data_cell = RelayCell { stream_id: 1, recognized: 0, digest: 0, command: RelayCommand::Data, data: buf[..n].to_vec() };
                            let Ok(mut payload) = bincode::serialize(&data_cell) else { break };
                            { let mut c = up_cipher.lock().await; c.apply_keystream(&mut payload); }
                            let cell = Cell { circ_id, command: CellCommand::Relay, payload };
                            let Ok(encoded) = bincode::serialize(&Message::TorCell(cell)) else { break };
                            let mut wr = up_relay_wr.lock().await;
                            if wr.write_all(&Packet::encapsulate(encoded)).await.is_err() { break; }
                        }
                        let mut wr = up_relay_wr.lock().await;
                        let _ = wr.shutdown().await;
                    });

                    let down_relay_rd = relay_rd.clone();
                    let down_cipher = down_bwd_cipher.clone();
                    let download = tokio::spawn(async move {
                        loop {
                            let mut rd = down_relay_rd.lock().await;
                            let packet = match Packet::decapsulate(&mut *rd).await { Ok(p) => p, Err(_) => break };
                            drop(rd);
                            let Ok(Message::TorCell(mut cell)) = bincode::deserialize::<Message>(&packet.payload) else { continue };
                            if cell.command != CellCommand::Relay { continue; }
                            { let mut c = down_cipher.lock().await; c.apply_keystream(&mut cell.payload); }
                            let Ok(relay_cell) = bincode::deserialize::<RelayCell>(&cell.payload) else { continue };
                            match relay_cell.command {
                                RelayCommand::Data => { if client_wr.write_all(&relay_cell.data).await.is_err() { break; } }
                                RelayCommand::End => break,
                                _ => {}
                            }
                        }
                        let _ = client_wr.shutdown().await;
                    });

                    let _ = tokio::join!(upload, download);
                }
            }
        });
    }
}

/// Initiates a multi-hop circuit establishment from the client (OP) perspective.
pub async fn establish_circuit(
    circ_id: CircuitId,
    path: Vec<SocketAddr>,
    client_config: Arc<ClientConfig>,
    directory: Arc<Directory>,
) -> Result<(Arc<RwLock<Circuit>>, tokio_rustls::client::TlsStream<TcpStream>), Box<dyn Error + Send + Sync>> {
    if path.is_empty() { return Err("Empty path".into()); }

    let mut stream = connect_to_peer(path[0], client_config.clone(), Some(&directory)).await?;
    
    // Hop 1 Handshake
    let rng = ring::rand::SystemRandom::new();
    let op_priv = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| "Keygen fail")?;
    let op_pub = op_priv.compute_public_key().map_err(|_| "Keygen fail")?;

    let create_cell = Cell { circ_id, command: CellCommand::Create, payload: op_pub.as_ref().to_vec() };
    stream.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(create_cell))?)).await?;

    let resp = Packet::decapsulate(&mut stream).await?;
    let (mut f_cipher, mut b_cipher) = if let Message::TorCell(cell) = bincode::deserialize(&resp.payload)? {
        let peer_pub = UnparsedPublicKey::new(&X25519, &cell.payload);
        let secret = agreement::agree_ephemeral(op_priv, &peer_pub, |m| {
            let hash = digest::digest(&digest::SHA256, m);
            let mut k = [0u8; 32]; k.copy_from_slice(hash.as_ref()); k
        }).map_err(|_| "Handshake fail")?;
        (Aes256Ctr::new(&secret.into(), &[0u8; 16].into()), Aes256Ctr::new(&secret.into(), &[0u8; 16].into()))
    } else { return Err("Invalid response".into()); };

    // Subsequent hops
    for hop_addr in path.iter().skip(1) {
        // Prepare EXTEND payload: [IP(4)] [Port(2)] [Pubkey(32)]
        let mut extend_payload = Vec::new();
        if let std::net::IpAddr::V4(ipv4) = hop_addr.ip() {
            extend_payload.extend_from_slice(&ipv4.octets());
        } else { return Err("IPv6 not supported".into()); }
        extend_payload.extend_from_slice(&hop_addr.port().to_be_bytes());
        
        let op_priv_n = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| "Keygen fail")?;
        let op_pub_n = op_priv_n.compute_public_key().map_err(|_| "Keygen fail")?;
        extend_payload.extend_from_slice(op_pub_n.as_ref());

        let relay_cell = RelayCell {
            stream_id: 0,
            recognized: 0,
            digest: 0,
            command: RelayCommand::Extend,
            data: extend_payload,
        };
        let mut payload = bincode::serialize(&relay_cell)?;
        f_cipher.apply_keystream(&mut payload);

        let cell = Cell { circ_id, command: CellCommand::Relay, payload };
        stream.write_all(&Packet::encapsulate(bincode::serialize(&Message::TorCell(cell))?)).await?;

        // Wait for EXTENDED
        let resp_packet = Packet::decapsulate(&mut stream).await?;
        let resp_msg: Message = bincode::deserialize(&resp_packet.payload)?;
        
        if let Message::TorCell(mut cell) = resp_msg {
            if cell.command == CellCommand::Relay {
                b_cipher.apply_keystream(&mut cell.payload);
                let extended_cell: RelayCell = bincode::deserialize(&cell.payload)?;
                if extended_cell.command == RelayCommand::Extended {
                    info!("Circuit extended to {}", hop_addr);
                } else { return Err("Unexpected relay command".into()); }
            } else { return Err("Unexpected cell".into()); }
        } else { return Err("Unexpected message".into()); }
    }

    let circuit = Circuit {
        id: circ_id,
        next_hop: Some(path[0]), 
        next_hop_stream: None,
        prev_hop: None,
        prev_hop_stream: None,
        forward_cipher: Some(f_cipher),
        backward_cipher: Some(b_cipher),
        streams: HashMap::new(),
        op_streams: HashMap::new(),
        package_window: CIRCUIT_WINDOW_START,
        deliver_window: CIRCUIT_WINDOW_START,
        linked_circuit_id: None,
    };
    let circuit_arc = Arc::new(RwLock::new(circuit));

    Ok((circuit_arc, stream))
}

/// Starts a hidden service that proxies traffic from the network to a local target.
/// Handles a single RELAY_INTRODUCE2 cell received on an introduction-point circuit:
/// parses the rendezvous point + cookie carried in the introduce data, connects to the
/// rendezvous point, completes the rendezvous handshake, and then bridges traffic
/// between the rendezvous circuit and the local `target_addr` service.
async fn handle_introduce2(
    data: Vec<u8>,
    target_addr: String,
    client_config: Arc<ClientConfig>,
    directory: Arc<Directory>,
) {
    // Expected layout (matches what the client's INTRODUCE1 sends and the relay's
    // INTRODUCE1 handler forwards verbatim): [service_key(32)][ip(4)][port(2)][cookie(20)]
    if data.len() < 58 {
        log::warn!("HS: malformed INTRODUCE2 payload ({} bytes)", data.len());
        return;
    }
    let rp_addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(data[32], data[33], data[34], data[35])),
        u16::from_be_bytes([data[36], data[37]]),
    );
    let cookie: [u8; 20] = match data[38..58].try_into() { Ok(c) => c, Err(_) => return };

    let circ_id: CircuitId = rand::random();
    let (circuit_arc, mut rp_stream) = match establish_circuit(circ_id, vec![rp_addr], client_config.clone(), directory.clone()).await {
        Ok(v) => v,
        Err(e) => { log::warn!("HS: failed to connect to rendezvous point {}: {}", rp_addr, e); return; }
    };
    let (mut forward_cipher, mut backward_cipher) = {
        let circuit = circuit_arc.read().await;
        match (circuit.forward_cipher.clone(), circuit.backward_cipher.clone()) {
            (Some(f), Some(b)) => (f, b),
            _ => return,
        }
    };

    let mut rend1_data = cookie.to_vec();
    rend1_data.extend_from_slice(&[0u8; 32]); // handshake material placeholder
    let rend1 = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::Rendezvous1, data: rend1_data };
    if send_relay_cell(&mut rp_stream, circ_id, &mut forward_cipher, &rend1).await.is_err() {
        log::warn!("HS: failed to send RENDEZVOUS1 to {}", rp_addr);
        return;
    }
    info!("HS: rendezvous established via {}, bridging to local service {}", rp_addr, target_addr);

    let mut local = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => { log::warn!("HS: failed to connect to local service {}: {}", target_addr, e); return; }
    };

    let (mut local_rd, mut local_wr) = local.split();
    let mut buf = [0u8; 4096];
    loop {
        tokio::select! {
            res = local_rd.read(&mut buf) => {
                let n = match res { Ok(0) | Err(_) => break, Ok(n) => n };
                let data_cell = RelayCell { stream_id: 1, recognized: 0, digest: 0, command: RelayCommand::Data, data: buf[..n].to_vec() };
                if send_relay_cell(&mut rp_stream, circ_id, &mut forward_cipher, &data_cell).await.is_err() { break; }
            }
            res = recv_relay_cell(&mut rp_stream, &mut backward_cipher) => {
                match res {
                    Ok(rc) if rc.command == RelayCommand::Data => { if local_wr.write_all(&rc.data).await.is_err() { break; } }
                    Ok(rc) if rc.command == RelayCommand::End => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }
}

/// Starts a hidden service that proxies traffic from the network to a local target.
///
/// `signing_key` is the hidden service's persistent Ed25519 identity key (see
/// `load_or_create_signing_key`), used to derive the `.root` address and sign the
/// published HS descriptor.
pub async fn start_hidden_service(
    target_addr: &str,
    directory: Arc<Directory>,
    client_config: Arc<ClientConfig>,
    signing_key: SigningKey,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Starting hidden service targeting {}...", target_addr);

    let verifying_key = VerifyingKey::from(&signing_key);
    let onion_addr = base32::encode(base32::Alphabet::RFC4648 { padding: false }, verifying_key.as_bytes()).to_lowercase();
    info!("Hidden service identity: {}.root", onion_addr);

    // Select introduction points from the directory.
    let mut relays = directory.get_all_relays().await;
    { let mut rng = thread_rng(); relays.shuffle(&mut rng); }
    let intro_relays: Vec<RelayDescriptor> = relays.into_iter().take(3).collect();

    if intro_relays.is_empty() {
        log::warn!("HS: no relays known in directory yet; will retry establishing introduction points periodically");
    }

    let mut intro_addrs = Vec::new();
    for relay in &intro_relays {
        let addr = relay.external_address;
        let circ_id: CircuitId = rand::random();
        let (circuit_arc, mut stream) = match establish_circuit(circ_id, vec![addr], client_config.clone(), directory.clone()).await {
            Ok(v) => v,
            Err(e) => { log::warn!("HS: failed to establish circuit to intro point {}: {}", addr, e); continue; }
        };
        let (mut forward_cipher, mut backward_cipher) = {
            let circuit = circuit_arc.read().await;
            match (circuit.forward_cipher.clone(), circuit.backward_cipher.clone()) {
                (Some(f), Some(b)) => (f, b),
                _ => continue,
            }
        };
        let establish_intro = RelayCell { stream_id: 0, recognized: 0, digest: 0, command: RelayCommand::EstablishIntro, data: verifying_key.as_bytes().to_vec() };
        if send_relay_cell(&mut stream, circ_id, &mut forward_cipher, &establish_intro).await.is_err() { continue; }
        match recv_relay_cell(&mut stream, &mut backward_cipher).await {
            Ok(rc) if rc.command == RelayCommand::IntroEstablished => {
                info!("HS: introduction point established at {}", addr);
                intro_addrs.push(addr);
            }
            _ => { log::warn!("HS: intro point {} did not confirm establishment", addr); continue; }
        }

        // Spawn a listener loop on this intro circuit for RELAY_INTRODUCE2 traffic.
        let target = target_addr.to_string();
        let cc = client_config.clone();
        let dc = directory.clone();
        tokio::spawn(async move {
            loop {
                match recv_relay_cell(&mut stream, &mut backward_cipher).await {
                    Ok(rc) if rc.command == RelayCommand::Introduce2 => {
                        let target2 = target.clone();
                        let cc2 = cc.clone();
                        let dc2 = dc.clone();
                        tokio::spawn(async move { handle_introduce2(rc.data, target2, cc2, dc2).await; });
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }

    // Build and sign the HS descriptor, then publish it into the gossip directory.
    let descriptor = HiddenServiceDescriptor::new(verifying_key, intro_addrs.clone(), &signing_key)?;
    directory.publish_hidden_service(descriptor).await;
    info!("HS: published descriptor for {}.root", onion_addr);

    // Keep the process alive; periodically re-publish so the descriptor doesn't
    // expire out of peers' directories.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        let refreshed = match HiddenServiceDescriptor::new(verifying_key, intro_addrs.clone(), &signing_key) {
            Ok(d) => d,
            Err(e) => { log::error!("HS: failed to re-sign descriptor: {}", e); continue; }
        };
        directory.publish_hidden_service(refreshed).await;
    }
}

pub fn get_bootstrap_nodes() -> Result<Vec<SocketAddr>, Box<dyn Error + Send + Sync>> {
    let bootstrap_addrs = std::env::var("BOOTSTRAP_NODES")
        .unwrap_or_else(|_| "127.0.0.1:8444,127.0.0.1:8445".to_string());
    
    let mut nodes = Vec::new();
    for addr_str in bootstrap_addrs.split(',') {
        if let Ok(mut addrs) = addr_str.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                nodes.push(addr);
            }
        }
    }
    Ok(nodes)
}

/// Dials a single peer address, sends our gossip packet, and (best-effort) reads
/// back a gossip reply, merging any learned relay descriptors into the directory
/// and peer store.
async fn gossip_with_addr(
    addr: SocketAddr,
    packet: &[u8],
    client_tls_config: Arc<ClientConfig>,
    directory: &Arc<Directory>,
    peer_store: &Arc<PeerStore>,
) {
    let mut stream = match connect_to_peer(addr, client_tls_config, Some(directory)).await {
        Ok(s) => s,
        Err(e) => { log::warn!("Gossip: failed to connect to {}: {}", addr, e); return; }
    };
    if let Err(e) = stream.write_all(packet).await {
        log::warn!("Gossip: failed to send to {}: {}", addr, e);
        return;
    }
    match time::timeout(time::Duration::from_secs(5), Packet::decapsulate(&mut stream)).await {
        Ok(Ok(reply_packet)) => {
            if let Ok(Message::Gossip(GossipMessage::Update(descriptors))) = bincode::deserialize::<Message>(&reply_packet.payload) {
                for d in descriptors {
                    if directory.add_relay(d.clone()).await {
                        if let Ok(info) = PeerInfo::new(d) {
                            peer_store.add_peer(info).await;
                        }
                    }
                }
            }
        }
        Ok(Err(e)) => log::debug!("Gossip: no reply from {}: {}", addr, e),
        Err(_) => log::debug!("Gossip: timed out waiting for reply from {}", addr),
    }
}

pub async fn start_gossip_task(our_relay_descriptor: RelayDescriptor, peer_store: Arc<PeerStore>, directory: Arc<Directory>, client_tls_config: Arc<ClientConfig>) {
    let mut interval = time::interval(time::Duration::from_secs(10));
    loop {
        interval.tick().await;
        directory.add_relay(our_relay_descriptor.clone()).await;

        let packet = match bincode::serialize(&Message::Gossip(GossipMessage::Update(directory.get_all_relays().await))) {
            Ok(encoded) => Packet::encapsulate(encoded),
            Err(e) => { log::error!("Gossip: failed to encode packet: {}", e); continue; }
        };

        // Gossip to a random subset of already-known peers.
        let connected_peers = peer_store.get_all_peers().await;
        let selected_peers: Vec<PeerInfo> = { let mut rng = thread_rng(); connected_peers.choose_multiple(&mut rng, 3).cloned().collect() };
        for peer in selected_peers {
            gossip_with_addr(peer.descriptor.external_address, &packet, client_tls_config.clone(), &directory, &peer_store).await;
        }

        // Also always try the configured bootstrap/seed nodes so a fresh node
        // with no known peers can still join the network.
        if let Ok(bootstrap_nodes) = get_bootstrap_nodes() {
            for addr in bootstrap_nodes {
                if addr == our_relay_descriptor.external_address { continue; }
                gossip_with_addr(addr, &packet, client_tls_config.clone(), &directory, &peer_store).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_packet_framing() {
        let original_data = b"Nebula Protocol Test".to_vec();
        let framed = Packet::encapsulate(original_data.clone());
        
        let mut cursor = std::io::Cursor::new(framed);
        let decapsulated = Packet::decapsulate(&mut cursor).await.unwrap();
        
        assert_eq!(decapsulated.payload, original_data);
    }

    #[tokio::test]
    async fn test_directory_logic() {
        let directory = Directory::new();
        
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let addr = "127.0.0.1:8080".parse().unwrap();
        
        let descriptor = RelayDescriptor::new(verifying_key, addr, vec![], &signing_key).unwrap();
        
        // Test valid add
        assert!(directory.add_relay(descriptor.clone()).await);
        
        // Test duplicate (should fail/return false due to timestamp not being newer)
        assert!(!directory.add_relay(descriptor).await);
        
        // Test updated timestamp
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let newer_descriptor = RelayDescriptor::new(verifying_key, addr, vec![], &signing_key).unwrap();
        assert!(directory.add_relay(newer_descriptor).await);
    }

    #[test]
    fn test_exit_policy_reject_all_default() {
        let policy = ExitPolicy::reject_all();
        assert!(!policy.is_allowed(std::net::Ipv4Addr::new(8, 8, 8, 8), 443));
    }

    #[test]
    fn test_exit_policy_parse_and_evaluate() {
        let text = "\
            # comment line\n\
            reject 127.0.0.0/8:*\n\
            reject *:25\n\
            accept *:*\n\
        ";
        let policy = ExitPolicy::parse(text).unwrap();
        // Loopback rejected regardless of port.
        assert!(!policy.is_allowed(std::net::Ipv4Addr::new(127, 0, 0, 1), 80));
        // SMTP rejected everywhere.
        assert!(!policy.is_allowed(std::net::Ipv4Addr::new(93, 184, 216, 34), 25));
        // Everything else accepted by the trailing wildcard.
        assert!(policy.is_allowed(std::net::Ipv4Addr::new(93, 184, 216, 34), 443));
    }

    #[test]
    fn test_exit_policy_implicit_final_reject() {
        let policy = ExitPolicy::parse("accept 10.0.0.0/8:*\n").unwrap();
        assert!(policy.is_allowed(std::net::Ipv4Addr::new(10, 1, 2, 3), 22));
        assert!(!policy.is_allowed(std::net::Ipv4Addr::new(8, 8, 8, 8), 22));
    }

    #[test]
    fn test_exit_policy_rejects_bad_syntax() {
        assert!(ExitPolicy::parse("maybe *:*\n").is_err());
        assert!(ExitPolicy::parse("accept not-an-ip:80\n").is_err());
        assert!(ExitPolicy::parse("accept *:notaport\n").is_err());
    }

    #[test]
    fn test_root_resolution() {
        // Generating a dummy key
        let key_bytes = [0u8; 32];
        let b32_key = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &key_bytes).to_lowercase();
        let domain = format!("{}.root", b32_key);
        
        let resolved = resolve_root_domain(&domain).unwrap();
        assert_eq!(resolved.to_bytes(), key_bytes);
    }
}
