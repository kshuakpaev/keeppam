use std::net::IpAddr;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ipnet::IpNet;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("пустой список защищённых целей")]
    EmptyTargets,
    #[error("политика просрочена")]
    Expired,
    #[error("режим политики не audit")]
    UnsupportedMode,
    #[error("некорректный адрес цели")]
    InvalidAddress,
    #[error("некорректный шлюз")]
    InvalidGateway,
    #[error("цель без адресов или портов")]
    InvalidTarget,
    #[error("подпись политики не принята")]
    BadSignature,
    #[error("ключ подписи не совпал с закреплённым")]
    KeyMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Audit,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedTarget {
    pub id: String,
    pub addresses: Vec<String>,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gateway {
    pub address: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub version: u64,
    pub mode: Mode,
    pub expires_at: Option<i64>,
    pub protected_targets: Vec<ProtectedTarget>,
    pub allowed_gateways: Vec<Gateway>,
}

impl Policy {
    pub fn normalized(mut self) -> Self {
        for target in &mut self.protected_targets {
            target.addresses.sort();
            target.ports.sort();
            target.ports.dedup();
        }
        self.protected_targets.sort_by(|a, b| a.id.cmp(&b.id));
        for gateway in &mut self.allowed_gateways {
            gateway.ports.sort();
            gateway.ports.dedup();
        }
        self.allowed_gateways
            .sort_by(|a, b| a.address.cmp(&b.address).then(a.ports.cmp(&b.ports)));
        self
    }

    pub fn id(&self) -> String {
        self.version.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    WouldDeny,
    Ignore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<i32>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub address: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEvent {
    pub event_id: String,
    pub event_type: String,
    pub observed_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<Destination>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicy {
    pub policy: Policy,
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub hostname: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub agent_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub hostname: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
    pub policy_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsRequest {
    pub events: Vec<EndpointEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsResponse {
    pub accepted: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingStart {
    pub id: String,
    pub destination: String,
    pub port: u16,
    pub username: String,
    pub started_at: i64,
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingChunk {
    pub t_ms: u64,
    pub direction: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingEnd {
    pub ended_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingAck {
    pub ok: bool,
}

pub struct ServiceKey {
    signing: SigningKey,
}

impl ServiceKey {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.signing.verifying_key().to_bytes())
    }

    pub fn sign(&self, policy: &Policy) -> SignedPolicy {
        let policy = policy.clone().normalized();
        let message = canonical_bytes(&policy);
        let signature = self.signing.sign(&message);
        SignedPolicy {
            policy,
            signature: STANDARD.encode(signature.to_bytes()),
            public_key: self.public_key_b64(),
        }
    }
}

pub fn canonical_bytes(policy: &Policy) -> Vec<u8> {
    let policy = policy.clone().normalized();
    let value = serde_json::to_value(&policy).expect("policy serializes");
    serde_json::to_vec(&value).expect("canonical json")
}

pub fn verify_signed(signed: &SignedPolicy) -> Result<(), ProtocolError> {
    let key_bytes = decode_exact::<32>(&signed.public_key)?;
    let sig_bytes = decode_exact::<64>(&signed.signature)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| ProtocolError::BadSignature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| ProtocolError::BadSignature)?;
    let message = canonical_bytes(&signed.policy);
    key.verify(&message, &signature)
        .map_err(|_| ProtocolError::BadSignature)
}

pub fn validate_publish(policy: &Policy, now: i64) -> Result<(), ProtocolError> {
    if policy.mode != Mode::Audit {
        return Err(ProtocolError::UnsupportedMode);
    }
    if policy.protected_targets.is_empty() {
        return Err(ProtocolError::EmptyTargets);
    }
    if let Some(expires_at) = policy.expires_at {
        if now >= expires_at {
            return Err(ProtocolError::Expired);
        }
    }
    for target in &policy.protected_targets {
        if target.id.trim().is_empty() || target.addresses.is_empty() || target.ports.is_empty() {
            return Err(ProtocolError::InvalidTarget);
        }
        if target.ports.iter().any(|port| *port == 0) {
            return Err(ProtocolError::InvalidTarget);
        }
        for address in &target.addresses {
            if address.parse::<IpNet>().is_err() && address.parse::<IpAddr>().is_err() {
                return Err(ProtocolError::InvalidAddress);
            }
        }
    }
    for gateway in &policy.allowed_gateways {
        if gateway.address.parse::<IpAddr>().is_err() || gateway.ports.is_empty() {
            return Err(ProtocolError::InvalidGateway);
        }
        if gateway.ports.iter().any(|port| *port == 0) {
            return Err(ProtocolError::InvalidGateway);
        }
    }
    Ok(())
}

pub fn evaluate(policy: &Policy, dest: IpAddr, port: u16, now: i64) -> Result<Decision, ProtocolError> {
    if policy.mode != Mode::Audit {
        return Err(ProtocolError::UnsupportedMode);
    }
    if policy.protected_targets.is_empty() {
        return Err(ProtocolError::EmptyTargets);
    }
    if let Some(expires_at) = policy.expires_at {
        if now >= expires_at {
            return Err(ProtocolError::Expired);
        }
    }
    if policy
        .allowed_gateways
        .iter()
        .any(|gateway| gateway_exact(gateway, dest, port))
    {
        return Ok(Decision::Allow);
    }
    if policy.protected_targets.iter().any(|target| {
        target.ports.contains(&port)
            && target
                .addresses
                .iter()
                .any(|address| address_matches(address, dest))
    }) {
        return Ok(Decision::WouldDeny);
    }
    Ok(Decision::Ignore)
}

fn gateway_exact(gateway: &Gateway, dest: IpAddr, port: u16) -> bool {
    let Ok(address) = gateway.address.parse::<IpAddr>() else {
        return false;
    };
    address == dest && gateway.ports.contains(&port)
}

fn address_matches(spec: &str, dest: IpAddr) -> bool {
    if let Ok(net) = spec.parse::<IpNet>() {
        return net.contains(&dest);
    }
    spec.parse::<IpAddr>().map(|ip| ip == dest).unwrap_or(false)
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], ProtocolError> {
    let bytes = STANDARD
        .decode(value.trim())
        .map_err(|_| ProtocolError::BadSignature)?;
    bytes
        .try_into()
        .map_err(|_| ProtocolError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(expires_at: Option<i64>) -> Policy {
        Policy {
            version: 1,
            mode: Mode::Audit,
            expires_at,
            protected_targets: vec![ProtectedTarget {
                id: "linux-prod-01".into(),
                addresses: vec!["10.10.10.20/32".into()],
                ports: vec![22, 23],
            }],
            allowed_gateways: vec![Gateway {
                address: "10.10.10.5".into(),
                ports: vec![2222, 2323],
            }],
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn signature_roundtrip_and_tamper() {
        let key = ServiceKey::generate();
        let signed = key.sign(&sample(None));
        assert!(verify_signed(&signed).is_ok());
        assert_eq!(signed.public_key, key.public_key_b64());

        let mut tampered = signed.clone();
        tampered.policy.version = 2;
        assert_eq!(verify_signed(&tampered), Err(ProtocolError::BadSignature));
    }

    #[test]
    fn canonical_json_is_stable_and_sorted() {
        let policy = sample(None);
        let first = canonical_bytes(&policy);
        let second = canonical_bytes(&policy);
        assert_eq!(first, second);
        let text = String::from_utf8(first).unwrap();
        assert!(text.starts_with("{\"allowed_gateways\":"));
    }

    #[test]
    fn empty_expired_and_enforce_are_rejected() {
        let mut empty = sample(None);
        empty.protected_targets.clear();
        assert_eq!(
            evaluate(&empty, ip("10.10.10.20"), 22, 0),
            Err(ProtocolError::EmptyTargets)
        );

        let expired = sample(Some(100));
        assert_eq!(
            evaluate(&expired, ip("10.10.10.20"), 22, 100),
            Err(ProtocolError::Expired)
        );

        let mut enforce = sample(None);
        enforce.mode = Mode::Enforce;
        assert_eq!(
            evaluate(&enforce, ip("10.10.10.20"), 22, 0),
            Err(ProtocolError::UnsupportedMode)
        );
    }

    #[test]
    fn protected_target_would_deny_and_exact_gateway_allows() {
        let policy = sample(None);
        assert_eq!(
            evaluate(&policy, ip("10.10.10.20"), 22, 0),
            Ok(Decision::WouldDeny)
        );
        assert_eq!(
            evaluate(&policy, ip("10.10.10.20"), 23, 0),
            Ok(Decision::WouldDeny)
        );
        assert_eq!(
            evaluate(&policy, ip("10.10.10.5"), 2222, 0),
            Ok(Decision::Allow)
        );
        assert_eq!(
            evaluate(&policy, ip("10.10.10.5"), 2323, 0),
            Ok(Decision::Allow)
        );
        assert_eq!(
            evaluate(&policy, ip("10.10.10.5"), 22, 0),
            Ok(Decision::Ignore)
        );
        assert_eq!(
            evaluate(&policy, ip("8.8.8.8"), 443, 0),
            Ok(Decision::Ignore)
        );
    }

    #[test]
    fn gateway_ip_on_a_protected_port_is_not_a_blanket_allow() {
        let mut policy = sample(None);
        policy.protected_targets[0].addresses = vec!["10.10.10.5/32".into()];
        assert_eq!(
            evaluate(&policy, ip("10.10.10.5"), 22, 0),
            Ok(Decision::WouldDeny)
        );
        assert_eq!(
            evaluate(&policy, ip("10.10.10.5"), 2222, 0),
            Ok(Decision::Allow)
        );
    }

    #[test]
    fn publish_rejects_empty_cidr_gateway_and_accepts_a_network() {
        let now = 1_000;
        let mut empty = sample(Some(2_000));
        empty.protected_targets.clear();
        assert_eq!(
            validate_publish(&empty, now),
            Err(ProtocolError::EmptyTargets)
        );

        let mut cidr_gateway = sample(Some(2_000));
        cidr_gateway.allowed_gateways[0].address = "10.10.10.0/24".into();
        assert_eq!(
            validate_publish(&cidr_gateway, now),
            Err(ProtocolError::InvalidGateway)
        );

        let mut network = sample(None);
        network.protected_targets[0].addresses = vec!["10.10.10.0/24".into()];
        assert!(validate_publish(&network, now).is_ok());
        assert_eq!(
            evaluate(&network, ip("10.10.10.21"), 22, now),
            Ok(Decision::WouldDeny)
        );
    }
}
