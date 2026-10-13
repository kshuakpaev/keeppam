use keeppam_agent_protocol::{
    verify_signed, Destination, EndpointEvent, EnrollRequest, EnrollResponse, EventsRequest,
    EventsResponse, HeartbeatRequest, HeartbeatResponse, ProcessInfo, ProtocolError, SignedPolicy,
};
use ureq::AgentBuilder;

use crate::AgentError;
use crate::Identity;

pub struct HttpPlane {
    base: String,
    agent: ureq::Agent,
}

impl HttpPlane {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            agent: AgentBuilder::new().redirects(0).build(),
        }
    }

    pub fn enroll(&self, token: &str, hostname: &str, version: &str) -> Result<Identity, AgentError> {
        let response = self
            .agent
            .post(&format!("{}/v1/enroll", self.base))
            .send_json(EnrollRequest {
                token: token.to_string(),
                hostname: hostname.to_string(),
                version: version.to_string(),
            })
            .map_err(map_ureq)?;
        let body: EnrollResponse = response
            .into_json()
            .map_err(|err| AgentError::Transport(err.to_string()))?;
        Ok(Identity {
            agent_id: body.agent_id,
            agent_secret: body.agent_secret,
        })
    }
}

impl crate::ControlPlane for HttpPlane {
    fn heartbeat(
        &self,
        identity: &Identity,
        hostname: &str,
        version: &str,
    ) -> Result<Option<u64>, AgentError> {
        let response = self
            .agent
            .post(&format!("{}/v1/agents/{}/heartbeat", self.base, identity.agent_id))
            .set("Authorization", &bearer(identity))
            .send_json(HeartbeatRequest {
                hostname: hostname.to_string(),
                version: version.to_string(),
            })
            .map_err(map_ureq)?;
        let body: HeartbeatResponse = response
            .into_json()
            .map_err(|err| AgentError::Transport(err.to_string()))?;
        Ok(body.policy_version)
    }

    fn fetch_policy(&self, identity: &Identity) -> Result<SignedPolicy, AgentError> {
        let response = self
            .agent
            .get(&format!("{}/v1/agents/{}/policy", self.base, identity.agent_id))
            .set("Authorization", &bearer(identity))
            .call()
            .map_err(map_ureq)?;
        response
            .into_json()
            .map_err(|err| AgentError::Transport(err.to_string()))
    }

    fn send_events(&self, identity: &Identity, events: &[EndpointEvent]) -> Result<(), AgentError> {
        let response = self
            .agent
            .post(&format!("{}/v1/agents/{}/events", self.base, identity.agent_id))
            .set("Authorization", &bearer(identity))
            .send_json(EventsRequest {
                events: events.to_vec(),
            })
            .map_err(map_ureq)?;
        let body: EventsResponse = response
            .into_json()
            .map_err(|err| AgentError::Transport(err.to_string()))?;
        if body.accepted != events.len() {
            return Err(AgentError::Status(502));
        }
        Ok(())
    }
}

fn bearer(identity: &Identity) -> String {
    format!("Bearer {}", identity.agent_secret)
}

fn map_ureq(err: ureq::Error) -> AgentError {
    match err {
        ureq::Error::Status(code, _) => AgentError::Status(code),
        other => AgentError::Transport(other.to_string()),
    }
}

pub fn accept_policy(pinned: &mut Option<String>, signed: &SignedPolicy) -> Result<(), ProtocolError> {
    verify_signed(signed)?;
    match pinned {
        Some(existing) if existing != &signed.public_key => Err(ProtocolError::KeyMismatch),
        None => {
            *pinned = Some(signed.public_key.clone());
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn observations_to_events(
    observations: &[keeppam_agent_monitor::Observation],
    policy: Option<&keeppam_agent_protocol::Policy>,
    now: i64,
) -> Vec<EndpointEvent> {
    observations
        .iter()
        .map(|observation| match observation {
            keeppam_agent_monitor::Observation::Process(process) => EndpointEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                event_type: "process.started".into(),
                observed_at: now,
                process: Some(ProcessInfo {
                    pid: process.pid,
                    parent_pid: Some(process.parent_pid),
                    name: trim_name(&process.name),
                }),
                destination: None,
                decision: None,
                policy_id: policy.map(|item| item.id()),
            },
            keeppam_agent_monitor::Observation::Tcp(flow) => {
                let decision = policy.and_then(|item| {
                    let addr = flow.address.parse().ok()?;
                    keeppam_agent_protocol::evaluate(item, addr, flow.port, now).ok()
                });
                EndpointEvent {
                    event_id: uuid::Uuid::new_v4().to_string(),
                    event_type: "connection.observed".into(),
                    observed_at: now,
                    process: Some(ProcessInfo {
                        pid: flow.pid,
                        parent_pid: None,
                        name: trim_name(&flow.name),
                    }),
                    destination: Some(Destination {
                        address: flow.address.clone(),
                        port: flow.port,
                        protocol: "tcp".into(),
                    }),
                    decision,
                    policy_id: policy.map(|item| item.id()),
                }
            }
        })
        .collect()
}

fn trim_name(name: &str) -> String {
    let trimmed: String = name.chars().take(128).collect();
    if trimmed.is_empty() {
        "unknown".into()
    } else {
        trimmed
    }
}
