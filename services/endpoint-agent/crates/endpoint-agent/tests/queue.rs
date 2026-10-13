use keeppam_agent_monitor::{Observation, TcpConnect};
use keeppam_agentd::testutil::TestServer;
use keeppam_endpoint_agent::{sync_once, HttpPlane, LocalState, Spool};

fn client() -> ureq::Agent {
    ureq::AgentBuilder::new().redirects(0).build()
}

fn login(agent: &ureq::Agent, base: &str) -> String {
    let response = agent
        .post(&format!("{base}/login"))
        .send_form(&[("username", "operator"), ("password", "secret")])
        .expect("login");
    assert_eq!(response.status(), 303);
    response
        .header("set-cookie")
        .expect("cookie")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string()
}

fn body_of(response: ureq::Response) -> String {
    response.into_string().unwrap_or_default()
}

#[test]
fn operator_page_and_spool_survive_outage() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("endpoint-e2e-{stamp}"));
    std::fs::create_dir_all(&root).unwrap();
    let mut server = runtime
        .block_on(TestServer::spawn(&root.join("server"), "operator", "secret"))
        .unwrap();
    let http = client();

    let rejected = http
        .post(&format!("{}/login", server.base))
        .send_form(&[("username", "operator"), ("password", "wrong")])
        .unwrap();
    assert!(body_of(rejected).contains("Неверное имя или пароль."));

    let cookie = login(&http, &server.base);
    let empty = http
        .post(&format!("{}/policy", server.base))
        .set("Cookie", &cookie)
        .send_form(&[("targets", ""), ("gateways", ""), ("expires_at", "")])
        .unwrap();
    assert!(body_of(empty).contains("пустой список защищённых целей"));

    let saved = http
        .post(&format!("{}/policy", server.base))
        .set("Cookie", &cookie)
        .send_form(&[
            ("targets", "linux-prod-01 | 10.10.10.20/32 | 22,23"),
            ("gateways", "10.10.10.5 | 2222,2323"),
            ("expires_at", ""),
        ])
        .unwrap();
    assert_eq!(saved.status(), 303);
    let policy_page = body_of(
        http.get(&format!("{}/policy?saved=1", server.base))
            .set("Cookie", &cookie)
            .call()
            .unwrap(),
    );
    assert!(policy_page.contains("id=\"policy-version\""));
    assert!(policy_page.contains("Версия 1"));

    let created = http
        .post(&format!("{}/enrollment", server.base))
        .set("Cookie", &cookie)
        .send_form(&[("create", "1")])
        .unwrap();
    assert_eq!(created.status(), 303);
    let location = created.header("location").unwrap().to_string();
    let token = location.split("token=").nth(1).unwrap().to_string();
    let agents_page = body_of(
        http.get(&format!("{}{location}", server.base))
            .set("Cookie", &cookie)
            .call()
            .unwrap(),
    );
    assert!(agents_page.contains("id=\"enrollment-token\""));
    assert!(agents_page.contains(&token));

    let state_dir = root.join("agent");
    std::fs::create_dir_all(&state_dir).unwrap();
    let plane = HttpPlane::new(&server.base);
    let identity = plane.enroll(&token, "workstation-a", "0.1.0").unwrap();
    let mut local = LocalState::load(&state_dir).unwrap();
    local.identity = Some(identity.clone());
    let mut spool = Spool::open(&state_dir.join("spool.sqlite")).unwrap();
    let protected = Observation::Tcp(TcpConnect {
        pid: 40,
        name: "ssh".into(),
        address: "10.10.10.20".into(),
        port: 22,
    });
    let report = sync_once(
        &plane,
        &mut spool,
        &identity,
        &mut local.signed_policy,
        &mut local.pinned_public_key,
        "workstation-a",
        "0.1.0",
        &[protected],
        1_700_000_000,
    )
    .unwrap();
    assert!(report.delivered);
    assert_eq!(report.policy_version, Some(1));

    let events = body_of(
        http.get(&format!("{}/events", server.base))
            .set("Cookie", &cookie)
            .call()
            .unwrap(),
    );
    assert!(events.contains("10.10.10.20"));
    assert!(events.contains("был бы запрет"));
    assert!(events.contains("data-decision=\"would_deny\""));
    let agents = body_of(
        http.get(&format!("{}/agents", server.base))
            .set("Cookie", &cookie)
            .call()
            .unwrap(),
    );
    assert!(agents.contains("workstation-a"));

    runtime.block_on(server.shutdown());
    let during_outage = Observation::Tcp(TcpConnect {
        pid: 41,
        name: "ssh".into(),
        address: "10.10.10.20".into(),
        port: 23,
    });
    let queued = sync_once(
        &plane,
        &mut spool,
        &identity,
        &mut local.signed_policy,
        &mut local.pinned_public_key,
        "workstation-a",
        "0.1.0",
        &[during_outage],
        1_700_000_100,
    )
    .unwrap();
    assert!(!queued.delivered);
    assert_eq!(spool.len().unwrap(), 1);

    let mut server = runtime
        .block_on(TestServer::spawn(&root.join("server"), "operator", "secret"))
        .unwrap();
    let plane = HttpPlane::new(&server.base);
    let cookie = login(&http, &server.base);
    let flushed = sync_once(
        &plane,
        &mut spool,
        &identity,
        &mut local.signed_policy,
        &mut local.pinned_public_key,
        "workstation-a",
        "0.1.0",
        &[],
        1_700_000_200,
    )
    .unwrap();
    assert!(flushed.delivered);
    assert_eq!(spool.len().unwrap(), 0);
    let events = body_of(
        http.get(&format!("{}/events", server.base))
            .set("Cookie", &cookie)
            .call()
            .unwrap(),
    );
    assert!(events.contains("Событий: 2"));
    assert!(events.contains("10.10.10.20:23"));
    runtime.block_on(server.shutdown());
}
