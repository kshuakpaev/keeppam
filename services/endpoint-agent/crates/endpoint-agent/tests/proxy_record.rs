use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use keeppam_agentd::testutil::TestServer;
use keeppam_endpoint_agent::{serve_proxy_stream, HttpPlane, LocalState};
use russh::server::{Auth, Session};
use russh::{ChannelId, CryptoVec};
use tokio::net::TcpListener;

const PASSWORD: &str = "pw-9f3c2a-do-not-store";
const MARKER: &str = "hello-session";

fn client() -> ureq::Agent {
    ureq::AgentBuilder::new().redirects(0).build()
}

fn login(agent: &ureq::Agent, base: &str) -> String {
    let response = agent
        .post(&format!("{base}/login"))
        .send_form(&[("username", "operator"), ("password", "secret")])
        .expect("login");
    response
        .header("set-cookie")
        .expect("cookie")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string()
}

struct Echo;

#[async_trait]
impl russh::server::Handler for Echo {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, CryptoVec::from_slice(data))?;
        Ok(())
    }
}

struct AcceptKey;

#[async_trait]
impl russh::client::Handler for AcceptKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[test]
fn proxy_uploads_terminal_text_for_replay() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("endpoint-proxy-{stamp}"));
    std::fs::create_dir_all(&root).unwrap();
    let mut server = runtime
        .block_on(TestServer::spawn(&root.join("server"), "operator", "secret"))
        .unwrap();
    let http = client();
    let cookie = login(&http, &server.base);
    let created = http
        .post(&format!("{}/enrollment", server.base))
        .set("Cookie", &cookie)
        .send_form(&[("create", "1")])
        .unwrap();
    let location = created.header("location").unwrap();
    let token = location.split("token=").nth(1).unwrap();
    let state_dir = root.join("agent");
    std::fs::create_dir_all(&state_dir).unwrap();
    let identity = HttpPlane::new(&server.base)
        .enroll(token, "workstation-a", "0.1.0")
        .unwrap();
    let mut local = LocalState::load(&state_dir).unwrap();
    local.identity = Some(identity);
    local.save(&state_dir).unwrap();

    let base = server.base.clone();
    runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(20), async {
                let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let echo_port = echo.local_addr().unwrap().port();
                let echo_key = russh::keys::PrivateKey::random(
                    &mut rand::rngs::OsRng,
                    russh::keys::Algorithm::Ed25519,
                )
                .unwrap();
                tokio::spawn(async move {
                    let (socket, _) = echo.accept().await.unwrap();
                    let config = Arc::new(russh::server::Config {
                        keys: vec![echo_key],
                        auth_rejection_time: Duration::from_millis(1),
                        auth_rejection_time_initial: Some(Duration::from_millis(1)),
                        ..Default::default()
                    });
                    let _ = russh::server::run_stream(config, socket, Echo).await;
                });

                let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let proxy_addr = proxy.local_addr().unwrap();
                let state = state_dir.clone();
                let service = base.clone();
                let proxy_task = tokio::spawn(async move {
                    let (socket, _) = proxy.accept().await.unwrap();
                    serve_proxy_stream(socket, "127.0.0.1", echo_port, &state, &service)
                        .await
                        .unwrap();
                });

                let mut session = russh::client::connect(
                    Arc::new(russh::client::Config {
                        inactivity_timeout: Some(Duration::from_secs(30)),
                        ..Default::default()
                    }),
                    proxy_addr,
                    AcceptKey,
                )
                .await
                .unwrap();
                assert!(session.authenticate_password("alice", PASSWORD).await.unwrap());
                let mut channel = session.channel_open_session().await.unwrap();
                channel.request_shell(true).await.unwrap();
                channel.data(&b"hello-session\n"[..]).await.unwrap();
                let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
                let mut seen = false;
                let mut trace = Vec::new();
                while tokio::time::Instant::now() < deadline {
                    let message = tokio::time::timeout(Duration::from_millis(500), channel.wait()).await;
                    match message {
                        Ok(Some(russh::ChannelMsg::Data { data })) => {
                            trace.push(format!("data:{}", String::from_utf8_lossy(&data)));
                            if data.windows(MARKER.len()).any(|item| item == MARKER.as_bytes()) {
                                seen = true;
                                break;
                            }
                        }
                        Ok(Some(other)) => trace.push(format!("{other:?}")),
                        Ok(None) => {
                            trace.push("closed".into());
                            break;
                        }
                        Err(_) => trace.push("wait-timeout".into()),
                    }
                }
                assert!(seen, "клиент не получил ответ терминала: {trace:?}");
                let _ = channel.eof().await;
                let _ = session
                    .disconnect(russh::Disconnect::ByApplication, "", "")
                    .await;
                proxy_task.await.unwrap();
            })
            .await
            .expect("таймаут прокси");
        });

    let list = http
        .get(&format!("{}/recordings", server.base))
        .set("Cookie", &cookie)
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(list.contains("127.0.0.1"), "{list}");
    assert!(list.contains("alice"), "{list}");
    assert!(!list.contains(PASSWORD), "{list}");
    let id = list
        .split("/recordings/")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("ссылка на запись");
    let replay = http
        .get(&format!("{}/recordings/{id}", server.base))
        .set("Cookie", &cookie)
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(replay.contains("id=\"session-screen\""), "{replay}");
    assert!(replay.contains(MARKER), "{replay}");
    assert!(!replay.contains(PASSWORD), "{replay}");
    runtime.block_on(server.shutdown());
}

#[test]
fn proxy_command_stdio_reaches_the_server() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("endpoint-proxy-stdio-{stamp}"));
    std::fs::create_dir_all(&root).unwrap();
    let mut server = runtime
        .block_on(TestServer::spawn(&root.join("server"), "operator", "secret"))
        .unwrap();
    let http = client();
    let cookie = login(&http, &server.base);
    let created = http
        .post(&format!("{}/enrollment", server.base))
        .set("Cookie", &cookie)
        .send_form(&[("create", "1")])
        .unwrap();
    let token = created.header("location").unwrap().split("token=").nth(1).unwrap();
    let state_dir = root.join("agent");
    std::fs::create_dir_all(&state_dir).unwrap();
    let identity = HttpPlane::new(&server.base)
        .enroll(token, "workstation-stdio", "0.1.0")
        .unwrap();
    let mut local = LocalState::load(&state_dir).unwrap();
    local.identity = Some(identity);
    local.save(&state_dir).unwrap();
    let base = server.base.clone();
    let state_for_child = state_dir.clone();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_port = echo.local_addr().unwrap().port();
            let echo_key = russh::keys::PrivateKey::random(
                &mut rand::rngs::OsRng,
                russh::keys::Algorithm::Ed25519,
            )
            .unwrap();
            tokio::spawn(async move {
                let (socket, _) = echo.accept().await.unwrap();
                let config = Arc::new(russh::server::Config {
                    keys: vec![echo_key],
                    auth_rejection_time: Duration::from_millis(1),
                    auth_rejection_time_initial: Some(Duration::from_millis(1)),
                    ..Default::default()
                });
                let _ = russh::server::run_stream(config, socket, Echo).await;
            });
            let mut agent_bin = std::env::current_exe().unwrap();
            agent_bin.pop();
            agent_bin.pop();
            agent_bin.push("endpoint-agent");
            let mut child = tokio::process::Command::new(agent_bin)
                .arg("proxy")
                .arg("--server")
                .arg(&base)
                .arg("--state-dir")
                .arg(&state_for_child)
                .arg("127.0.0.1")
                .arg(echo_port.to_string())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let stdin = child.stdin.take().unwrap();
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let logged = Arc::new(std::sync::Mutex::new(String::new()));
            let logged_task = Arc::clone(&logged);
            tokio::spawn(async move {
                let mut stderr = stderr;
                let mut buf = Vec::new();
                let _ = tokio::io::AsyncReadExt::read_to_end(&mut stderr, &mut buf).await;
                *logged_task.lock().unwrap() = String::from_utf8_lossy(&buf).into_owned();
            });
            let stream = tokio::io::join(stdout, stdin);
            let mut session = russh::client::connect_stream(
                Arc::new(russh::client::Config {
                    inactivity_timeout: Some(Duration::from_secs(30)),
                    ..Default::default()
                }),
                stream,
                AcceptKey,
            )
            .await
            .unwrap_or_else(|err| panic!("stdio прокси не ответил: {err}; {}", logged.lock().unwrap()));
            assert!(session.authenticate_password("alice", PASSWORD).await.unwrap());
            let mut channel = session.channel_open_session().await.unwrap();
            channel.request_shell(true).await.unwrap();
            channel.data(&b"hello-session\n"[..]).await.unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            let mut seen = false;
            let mut trace = Vec::new();
            while tokio::time::Instant::now() < deadline {
                let message = tokio::time::timeout(Duration::from_millis(500), channel.wait()).await;
                match message {
                    Ok(Some(russh::ChannelMsg::Data { data })) => {
                        trace.push(format!("data:{}", String::from_utf8_lossy(&data)));
                        if data.windows(MARKER.len()).any(|item| item == MARKER.as_bytes()) {
                            seen = true;
                            break;
                        }
                    }
                    Ok(Some(other)) => trace.push(format!("{other:?}")),
                    Ok(None) => {
                        trace.push("closed".into());
                        break;
                    }
                    Err(_) => trace.push("wait-timeout".into()),
                }
            }
            assert!(
                seen,
                "stdio прокси не дошёл до сервера: {trace:?}; {}",
                logged.lock().unwrap()
            );
            let _ = channel.eof().await;
            let _ = session.disconnect(russh::Disconnect::ByApplication, "", "").await;
            let _ = child.wait().await;
        })
        .await
        .expect("таймаут stdio прокси");
    });
    runtime.block_on(server.shutdown());
}
