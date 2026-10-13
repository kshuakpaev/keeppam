use keeppam_agent_protocol::SignedPolicy;

use crate::http_plane::{accept_policy, observations_to_events};
use crate::spool::Spool;
use crate::{AgentError, ControlPlane, Identity};

pub struct SyncReport {
    pub delivered: bool,
    pub queued_remaining: usize,
    pub policy_version: Option<u64>,
    pub policy_rejected: bool,
}

pub fn sync_once(
    api: &dyn ControlPlane,
    spool: &mut Spool,
    identity: &Identity,
    signed_policy: &mut Option<SignedPolicy>,
    pinned_key: &mut Option<String>,
    hostname: &str,
    version: &str,
    observations: &[keeppam_agent_monitor::Observation],
    now: i64,
) -> Result<SyncReport, AgentError> {
    let remote_version = match api.heartbeat(identity, hostname, version) {
        Ok(version) => version,
        Err(AgentError::Transport(_)) => {
            let events = observations_to_events(observations, policy_of(signed_policy), now);
            spool.enqueue(&events, now)?;
            return Ok(report(false, spool, signed_policy, false));
        }
        Err(err) => return Err(err),
    };

    let mut policy_rejected = false;
    let local_version = signed_policy.as_ref().map(|item| item.policy.version);
    if remote_version.is_some() && local_version != remote_version {
        match api.fetch_policy(identity) {
            Ok(signed) => match accept_policy(pinned_key, &signed) {
                Ok(()) => *signed_policy = Some(signed),
                Err(_) => policy_rejected = true,
            },
            Err(AgentError::Status(404)) => {}
            Err(AgentError::Transport(_)) => {
                let events = observations_to_events(observations, policy_of(signed_policy), now);
                spool.enqueue(&events, now)?;
                return Ok(report(false, spool, signed_policy, false));
            }
            Err(err) => return Err(err),
        }
    }

    let events = observations_to_events(observations, policy_of(signed_policy), now);
    spool.enqueue(&events, now)?;
    flush(api, spool, identity, signed_policy, policy_rejected)
}

fn flush(
    api: &dyn ControlPlane,
    spool: &mut Spool,
    identity: &Identity,
    signed_policy: &Option<SignedPolicy>,
    policy_rejected: bool,
) -> Result<SyncReport, AgentError> {
    let pending = spool.peek(200)?;
    if pending.is_empty() {
        return Ok(report(true, spool, signed_policy, policy_rejected));
    }
    let batch = pending
        .iter()
        .map(|(_, event)| event.clone())
        .collect::<Vec<_>>();
    match api.send_events(identity, &batch) {
        Ok(()) => {
            let ids = pending.iter().map(|(id, _)| *id).collect::<Vec<_>>();
            spool.delete(&ids)?;
            Ok(report(true, spool, signed_policy, policy_rejected))
        }
        Err(AgentError::Transport(_)) => Ok(report(false, spool, signed_policy, policy_rejected)),
        Err(err) => Err(err),
    }
}

fn policy_of(signed: &Option<SignedPolicy>) -> Option<&keeppam_agent_protocol::Policy> {
    signed.as_ref().map(|item| &item.policy)
}

fn report(
    delivered: bool,
    spool: &Spool,
    signed_policy: &Option<SignedPolicy>,
    policy_rejected: bool,
) -> SyncReport {
    SyncReport {
        delivered,
        queued_remaining: spool.len().unwrap_or(0),
        policy_version: signed_policy.as_ref().map(|item| item.policy.version),
        policy_rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keeppam_agent_monitor::{Observation, TcpConnect};
    use keeppam_agent_protocol::{Gateway, Mode, Policy, ProtectedTarget, ServiceKey};
    use std::path::PathBuf;

    struct Fake {
        up: bool,
        signed: SignedPolicy,
    }

    impl ControlPlane for Fake {
        fn heartbeat(
            &self,
            _: &Identity,
            _: &str,
            _: &str,
        ) -> Result<Option<u64>, AgentError> {
            if self.up {
                Ok(Some(self.signed.policy.version))
            } else {
                Err(AgentError::Transport("down".into()))
            }
        }

        fn fetch_policy(&self, _: &Identity) -> Result<SignedPolicy, AgentError> {
            if self.up {
                Ok(self.signed.clone())
            } else {
                Err(AgentError::Transport("down".into()))
            }
        }

        fn send_events(&self, _: &Identity, events: &[keeppam_agent_protocol::EndpointEvent]) -> Result<(), AgentError> {
            if !self.up {
                return Err(AgentError::Transport("down".into()));
            }
            let _ = events;
            Ok(())
        }
    }

    fn sample_signed() -> SignedPolicy {
        let policy = Policy {
            version: 1,
            mode: Mode::Audit,
            expires_at: None,
            protected_targets: vec![ProtectedTarget {
                id: "linux-prod-01".into(),
                addresses: vec!["10.10.10.20/32".into()],
                ports: vec![22],
            }],
            allowed_gateways: vec![Gateway {
                address: "10.10.10.5".into(),
                ports: vec![2222],
            }],
        };
        // version is assigned by the signer as stored on the policy object.
        let mut policy = policy;
        policy.version = 3;
        ServiceKey::generate().sign(&policy)
    }

    fn temp_spool() -> (PathBuf, Spool) {
        let dir = std::env::temp_dir().join(format!("endpoint-spool-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let spool = Spool::open(&dir.join("spool.sqlite")).unwrap();
        (dir, spool)
    }

    #[test]
    fn outage_keeps_the_event_until_the_service_returns() {
        let signed = sample_signed();
        let identity = Identity {
            agent_id: "agent".into(),
            agent_secret: "secret".into(),
        };
        let (_dir, mut spool) = temp_spool();
        let mut policy = None;
        let mut pinned = None;
        let observation = Observation::Tcp(TcpConnect {
            pid: 10,
            name: "ssh".into(),
            address: "10.10.10.20".into(),
            port: 22,
        });
        let mut fake = Fake {
            up: false,
            signed: signed.clone(),
        };
        let queued = sync_once(
            &fake,
            &mut spool,
            &identity,
            &mut policy,
            &mut pinned,
            "host",
            "0.1.0",
            &[observation],
            50,
        )
        .unwrap();
        assert!(!queued.delivered);
        assert_eq!(spool.len().unwrap(), 1);

        fake.up = true;
        let delivered = sync_once(
            &fake,
            &mut spool,
            &identity,
            &mut policy,
            &mut pinned,
            "host",
            "0.1.0",
            &[],
            51,
        )
        .unwrap();
        assert!(delivered.delivered);
        assert_eq!(spool.len().unwrap(), 0);
        assert_eq!(
            policy.as_ref().map(|item| item.policy.version),
            Some(signed.policy.version)
        );
    }
}
