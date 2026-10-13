use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use russh::client::Msg as ClientMsg;
use russh::server::{Auth, Msg as ServerMsg, Session};
use russh::{ChannelId, ChannelMsg, CryptoVec, Disconnect};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;

use crate::state::{restrict, LocalState};
use crate::upload::{UploadItem, UploadWorker};
use crate::AgentError;

const MARK_BEGIN: &str = "# BEGIN keeppam-endpoint-agent";
const MARK_END: &str = "# END keeppam-endpoint-agent";

pub async fn serve_proxy_stream<S>(
    stream: S,
    destination: &str,
    port: u16,
    state_dir: &Path,
    server_url: &str,
) -> Result<(), AgentError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let destination = destination.trim();
    if destination.is_empty() || destination.chars().any(|ch| ch.is_control()) || port == 0 {
        return Err(AgentError::Proxy("некорректное назначение".into()));
    }
    std::fs::create_dir_all(state_dir).map_err(|err| AgentError::State(err.to_string()))?;
    note(state_dir, &format!("сессия {destination}:{port}"));
    let local = LocalState::load(state_dir)?;
    if local.identity.is_none() {
        eprintln!("прокси: агент не зачислен, сессия идёт на сервер без отправки записи");
    }
    let host_key = load_host_key(state_dir)?;
    let tasks: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let worker = UploadWorker::start(
        server_url.to_string(),
        state_dir.to_path_buf(),
        local.identity,
    );
    let bridge = Bridge {
        destination: destination.to_string(),
        port,
        upload: worker.sender(),
        to_upstream: None,
        client_side: Arc::new(Mutex::new(None)),
        tasks: Arc::clone(&tasks),
        recording_id: None,
        started: Instant::now(),
        cancel: None,
    };
    let config = proxy_server_config(host_key);
    let run_result = async {
        let running = russh::server::run_stream(config, stream, bridge)
            .await
            .map_err(|err| AgentError::Proxy(err.to_string()))?;
        running
            .await
            .map_err(|err| AgentError::Proxy(err.to_string()))?;
        Ok(())
    }
    .await;
    let run_result = match run_result {
        Err(err) if client_closed(&err) => Ok(()),
        other => other,
    };
    let upstream = tasks.lock().expect("задача прокси").take();
    if let Some(handle) = upstream {
        let _ = handle.await;
    }
    worker.finish();
    run_result
}

pub fn run_proxy(args: &[String]) -> Result<(), AgentError> {
    let opts = parse_opts(args)?;
    if opts.rest.len() != 2 {
        return Err(AgentError::Proxy(
            "использование: endpoint-agent proxy --server URL --state-dir DIR HOST PORT".into(),
        ));
    }
    let destination = opts.rest[0].clone();
    let port: u16 = opts.rest[1]
        .parse()
        .map_err(|_| AgentError::Proxy("некорректный порт".into()))?;
    #[cfg(windows)]
    binary_stdio();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| AgentError::Proxy(err.to_string()))?;
    runtime.block_on(async move {
        let stream = ProxyStdio::new();
        serve_proxy_stream(stream, &destination, port, &opts.state_dir, &opts.server_url).await
    })
}

struct ProxyStdio {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
    pending_flush: Option<usize>,
}

impl ProxyStdio {
    fn new() -> Self {
        Self {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
            pending_flush: None,
        }
    }
}

impl AsyncRead for ProxyStdio {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStdio {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(sent) = self.pending_flush {
            std::task::ready!(Pin::new(&mut self.stdout).poll_flush(cx))?;
            self.pending_flush = None;
            return Poll::Ready(Ok(sent));
        }
        let sent = std::task::ready!(Pin::new(&mut self.stdout).poll_write(cx, buf))?;
        match Pin::new(&mut self.stdout).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(sent)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                self.pending_flush = Some(sent);
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(Pin::new(&mut self.stdout).poll_flush(cx))?;
        self.pending_flush = None;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}

pub fn run_install(args: &[String]) -> Result<(), AgentError> {
    let opts = parse_opts(args)?;
    if !opts.rest.is_empty() {
        return Err(AgentError::Proxy(
            "использование: endpoint-agent install-proxy --server URL --state-dir DIR".into(),
        ));
    }
    require_enrolled(&opts.state_dir)?;
    let message = enable_redirect(&opts.server_url, &opts.state_dir, opts.ssh_config.as_deref())?;
    eprintln!("{message}");
    Ok(())
}

pub(crate) fn enable_redirect(
    server_url: &str,
    state_dir: &Path,
    ssh_config: Option<&Path>,
) -> Result<String, AgentError> {
    std::fs::create_dir_all(state_dir).map_err(|err| AgentError::State(err.to_string()))?;
    let exe = std::env::current_exe().map_err(|err| AgentError::Proxy(err.to_string()))?;
    let command = proxy_command(&exe, server_url, state_dir, "%h", "%p")?;
    let known_hosts = state_dir.join("known_hosts");
    let block = ssh_block(&command, &known_hosts);
    let config_path = match ssh_config {
        Some(path) => path.to_path_buf(),
        None => default_ssh_config()?,
    };
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| AgentError::State(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let existing = if config_path.exists() {
        std::fs::read_to_string(&config_path).map_err(|err| AgentError::State(err.to_string()))?
    } else {
        String::new()
    };
    let updated = upsert_block(&existing, &block);
    std::fs::write(&config_path, &updated).map_err(|err| AgentError::State(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut message = format!("перехват SSH включён: {}", config_path.display());
    #[cfg(windows)]
    {
        let putty = proxy_command(&exe, server_url, state_dir, "%host", "%port")?;
        let sessions = install_putty(&putty)?;
        message.push_str(&format!(", PuTTY сессий: {sessions}"));
    }
    note(state_dir, &message);
    note(state_dir, &command);
    Ok(message)
}

fn note(dir: &Path, line: &str) {
    use std::io::Write;
    let path = dir.join("proxy.log");
    let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = writeln!(file, "{line}");
}

pub fn run_uninstall(args: &[String]) -> Result<(), AgentError> {
    let opts = parse_opts(args)?;
    if !opts.rest.is_empty() {
        return Err(AgentError::Proxy(
            "использование: endpoint-agent uninstall-proxy".into(),
        ));
    }
    let path = match opts.ssh_config {
        Some(path) => path,
        None => default_ssh_config()?,
    };
    disable_redirect_at(&path)
}

pub fn disable_redirect() -> Result<(), AgentError> {
    disable_redirect_at(&default_ssh_config()?)
}

fn disable_redirect_at(config_path: &Path) -> Result<(), AgentError> {
    if config_path.exists() {
        let existing =
            std::fs::read_to_string(config_path).map_err(|err| AgentError::State(err.to_string()))?;
        let updated = remove_block(&existing);
        if updated != existing {
            std::fs::write(config_path, updated).map_err(|err| AgentError::State(err.to_string()))?;
        }
        eprintln!("OpenSSH: перехват агента снят ({})", config_path.display());
    }
    #[cfg(windows)]
    {
        let sessions = clear_putty()?;
        eprintln!("PuTTY: прямое подключение восстановлено ({sessions})");
    }
    Ok(())
}

struct Opts {
    server_url: String,
    state_dir: PathBuf,
    ssh_config: Option<PathBuf>,
    rest: Vec<String>,
}

fn parse_opts(args: &[String]) -> Result<Opts, AgentError> {
    let mut server_url =
        std::env::var("AGENT_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8090".into());
    let mut state_dir = std::env::var("AGENT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("agent-state"));
    let mut ssh_config = None;
    let mut rest = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let (key, inline) = split_arg(arg);
        let mut take = || -> Result<String, AgentError> {
            if let Some(value) = inline.clone() {
                return Ok(value);
            }
            index += 1;
            args.get(index)
                .cloned()
                .ok_or_else(|| AgentError::Proxy(format!("нет значения для {key}")))
        };
        match key.as_str() {
            "--server" => server_url = take()?,
            "--state-dir" => state_dir = PathBuf::from(take()?),
            "--ssh-config" => ssh_config = Some(PathBuf::from(take()?)),
            other if other.starts_with('-') => {
                return Err(AgentError::Proxy(format!("неизвестный аргумент {other}")));
            }
            other => rest.push(other.to_string()),
        }
        index += 1;
    }
    Ok(Opts {
        server_url,
        state_dir,
        ssh_config,
        rest,
    })
}

fn split_arg(arg: &str) -> (String, Option<String>) {
    if let Some((key, value)) = arg.split_once('=') {
        if key.starts_with("--") {
            return (key.to_string(), Some(value.to_string()));
        }
    }
    (arg.to_string(), None)
}

fn require_enrolled(state_dir: &Path) -> Result<(), AgentError> {
    let local = LocalState::load(state_dir)?;
    if local.identity.is_none() {
        return Err(AgentError::Proxy(format!(
            "в каталоге {} нет зачисленного агента. Найдите state.json там, откуда агент уже отправляет события (часто это папка agent-state рядом с программой), и повторите команду с этим каталогом",
            state_dir.display()
        )));
    }
    Ok(())
}

fn config_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn proxy_command(
    exe: &Path,
    server: &str,
    state_dir: &Path,
    host_token: &str,
    port_token: &str,
) -> Result<String, AgentError> {
    if server.chars().any(|ch| ch.is_whitespace()) {
        return Err(AgentError::Proxy("адрес сервиса содержит пробел".into()));
    }
    Ok(format!(
        "{} proxy --server {server} --state-dir {} {host_token} {port_token}",
        shell_quote(&config_path(exe))?,
        shell_quote(&config_path(state_dir))?
    ))
}

fn shell_quote(value: &str) -> Result<String, AgentError> {
    if value.contains('"') || value.contains('\n') || value.contains('\r') {
        return Err(AgentError::Proxy("путь содержит кавычки".into()));
    }
    Ok(format!("\"{value}\""))
}

fn ssh_block(command: &str, known_hosts: &Path) -> String {
    format!(
        "{MARK_BEGIN}\n# Сессии SSH завершаются на агенте и уходят в сервис записей.\nHost *\n    ProxyCommand {command}\n    StrictHostKeyChecking accept-new\n    UserKnownHostsFile {}\n{MARK_END}\n",
        shell_quote(&config_path(known_hosts)).unwrap_or_else(|_| "\"known_hosts\"".into())
    )
}

fn upsert_block(existing: &str, block: &str) -> String {
    let block = block.trim();
    let rest = remove_block(existing);
    let rest = rest.trim_start_matches(['\r', '\n']);
    let mut out = String::new();
    out.push_str(block);
    out.push('\n');
    if !rest.is_empty() {
        out.push('\n');
        out.push_str(rest);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn remove_block(existing: &str) -> String {
    let Some(start) = existing.find(MARK_BEGIN) else {
        return existing.to_string();
    };
    let Some(end_rel) = existing[start..].find(MARK_END) else {
        return existing.to_string();
    };
    let end = start + end_rel + MARK_END.len();
    let mut out = existing[..start].trim_end().to_string();
    let rest = existing[end..].trim_start_matches(['\r', '\n']);
    if rest.is_empty() {
        if out.is_empty() {
            return String::new();
        }
        out.push('\n');
        return out;
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(rest);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn default_ssh_config() -> Result<PathBuf, AgentError> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| AgentError::Proxy("нет домашнего каталога".into()))?;
    Ok(PathBuf::from(home).join(".ssh").join("config"))
}

#[cfg(windows)]
fn install_putty(command: &str) -> Result<usize, AgentError> {
    let keys = putty_session_keys();
    for key in &keys {
        run_reg(&[
            "add",
            key,
            "/v",
            "ProxyMethod",
            "/t",
            "REG_DWORD",
            "/d",
            "5",
            "/f",
        ])?;
        run_reg(&[
            "add",
            key,
            "/v",
            "ProxyTelnetCommand",
            "/t",
            "REG_SZ",
            "/d",
            command,
            "/f",
        ])?;
    }
    Ok(keys.len())
}

#[cfg(windows)]
fn clear_putty() -> Result<usize, AgentError> {
    let mut cleared = 0usize;
    for key in putty_session_keys() {
        let Some(command) = putty_command(&key) else {
            continue;
        };
        if !command.contains("endpoint-agent") && !command.contains("keeppam") {
            continue;
        }
        run_reg(&[
            "add",
            &key,
            "/v",
            "ProxyMethod",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ])?;
        run_reg(&[
            "add",
            &key,
            "/v",
            "ProxyTelnetCommand",
            "/t",
            "REG_SZ",
            "/d",
            "",
            "/f",
        ])?;
        cleared += 1;
    }
    Ok(cleared)
}

#[cfg(windows)]
fn putty_command(key: &str) -> Option<String> {
    let output = std::process::Command::new("reg")
        .args(["query", key, "/v", "ProxyTelnetCommand"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().find_map(|line| {
        let line = line.trim();
        let marker = "REG_SZ";
        let index = line.find(marker)?;
        Some(line[index + marker.len()..].trim().to_string())
    })
}

#[cfg(windows)]
fn putty_session_keys() -> Vec<String> {
    let fallback = || vec![r"HKCU\Software\SimonTatham\PuTTY\Sessions\Default%20Settings".to_string()];
    let output = match std::process::Command::new("reg")
        .args(["query", r"HKCU\Software\SimonTatham\PuTTY\Sessions"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return fallback(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let keys: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("HKEY_"))
        .map(str::to_string)
        .collect();
    if keys.is_empty() {
        fallback()
    } else {
        keys
    }
}

#[cfg(windows)]
fn run_reg(args: &[&str]) -> Result<(), AgentError> {
    let output = std::process::Command::new("reg")
        .args(args)
        .output()
        .map_err(|err| AgentError::Proxy(err.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        if detail.is_empty() {
            Err(AgentError::Proxy("не удалось записать настройки PuTTY".into()))
        } else {
            Err(AgentError::Proxy(format!(
                "не удалось записать настройки PuTTY: {detail}"
            )))
        }
    }
}

#[cfg(windows)]
fn binary_stdio() {
    unsafe {
        extern "C" {
            fn _setmode(fd: i32, mode: i32) -> i32;
        }
        const O_BINARY: i32 = 0x8000;
        _setmode(0, O_BINARY);
        _setmode(1, O_BINARY);
    }
}

fn load_host_key(dir: &Path) -> Result<russh::keys::PrivateKey, AgentError> {
    let path = dir.join("proxy_host_key");
    if path.exists() {
        let pem = std::fs::read(&path).map_err(|err| AgentError::Proxy(err.to_string()))?;
        return russh::keys::PrivateKey::from_openssh(&pem)
            .map_err(|err| AgentError::Proxy(err.to_string()));
    }
    let mut rng = rand::rngs::OsRng;
    let key = russh::keys::PrivateKey::random(&mut rng, russh::keys::Algorithm::Ed25519)
        .map_err(|err| AgentError::Proxy(err.to_string()))?;
    let pem = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|err| AgentError::Proxy(err.to_string()))?;
    std::fs::write(&path, pem.as_bytes()).map_err(|err| AgentError::Proxy(err.to_string()))?;
    restrict(&path);
    Ok(key)
}

fn password_methods() -> russh::MethodSet {
    russh::MethodSet::PASSWORD | russh::MethodSet::KEYBOARD_INTERACTIVE
}

fn reject_password() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(password_methods()),
    }
}

fn proxy_server_config(key: russh::keys::PrivateKey) -> Arc<russh::server::Config> {
    Arc::new(russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::from_millis(1)),
        keys: vec![key],
        methods: password_methods(),
        event_buffer_size: 64,
        ..Default::default()
    })
}

fn client_config() -> Arc<russh::client::Config> {
    Arc::new(russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    })
}

enum UpCmd {
    Pty {
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: Vec<(russh::Pty, u32)>,
    },
    Shell,
    Exec(Vec<u8>),
    Data(Vec<u8>),
    Extended { ext: u32, data: Vec<u8> },
    Window { col_width: u32, row_height: u32, pix_width: u32, pix_height: u32 },
    Eof,
    Close,
}

struct Bridge {
    destination: String,
    port: u16,
    upload: mpsc::Sender<UploadItem>,
    to_upstream: Option<mpsc::Sender<UpCmd>>,
    client_side: Arc<Mutex<Option<(ChannelId, russh::server::Handle)>>>,
    tasks: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    recording_id: Option<String>,
    started: Instant,
    cancel: Option<oneshot::Sender<()>>,
}

struct AcceptAnyKey;

#[async_trait]
impl russh::client::Handler for AcceptAnyKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Агент — граница доверия: клиент закрепляет ключ прокси, а не ключ дальнего сервера.
        Ok(true)
    }
}

impl Bridge {
    async fn command(&self, cmd: UpCmd) -> bool {
        let Some(tx) = &self.to_upstream else {
            return false;
        };
        tx.send(cmd).await.is_ok()
    }

    async fn record(&self, direction: &str, data: &[u8]) {
        let Some(id) = &self.recording_id else {
            return;
        };
        if data.is_empty() {
            return;
        }
        let _ = self
            .upload
            .send(UploadItem::Chunk {
                id: id.clone(),
                t_ms: elapsed_ms(self.started),
                direction: direction.to_string(),
                data: data.to_vec(),
            })
            .await;
    }

    async fn open_upstream(&mut self, user: &str, password: &str) -> Auth {
        let destination = self.destination.clone();
        let port = self.port;
        let connect = russh::client::connect(
            client_config(),
            (destination.as_str(), port),
            AcceptAnyKey,
        )
        .await;
        let mut upstream = match connect {
            Ok(session) => session,
            Err(err) => {
                eprintln!("прокси: {destination}:{port} недоступен: {err}");
                return reject_password();
            }
        };
        match upstream.authenticate_password(user, password).await {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("прокси: {destination}:{port} не принял пароль");
                return reject_password();
            }
            Err(err) => {
                eprintln!("прокси: {destination}:{port} ошибка входа: {err}");
                return reject_password();
            }
        }
        let channel = match upstream.channel_open_session().await {
            Ok(channel) => channel,
            Err(err) => {
                eprintln!("прокси: канал к {destination}:{port} не открыт: {err}");
                return reject_password();
            }
        };
        let recording_id = Uuid::new_v4().to_string();
        let started_at = unix_now();
        if self
            .upload
            .send(UploadItem::Start {
                id: recording_id.clone(),
                destination: destination.clone(),
                port,
                username: user.to_string(),
                started_at,
                kind: String::new(),
            })
            .await
            .is_err()
        {
            eprintln!("прокси: очередь записи закрыта");
        }
        eprintln!("запись {recording_id} → {destination}:{port} пользователь {user}");
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let upload = self.upload.clone();
        let client_side = Arc::clone(&self.client_side);
        let started = self.started;
        let id_for_task = recording_id.clone();
        let task = tokio::spawn(async move {
            upstream_loop(
                upstream,
                channel,
                cmd_rx,
                cancel_rx,
                client_side,
                upload,
                id_for_task,
                started,
            )
            .await;
        });
        *self.tasks.lock().expect("задача прокси") = Some(task);
        self.to_upstream = Some(cmd_tx);
        self.cancel = Some(cancel_tx);
        self.recording_id = Some(recording_id);
        Auth::Accept
    }
}

async fn upstream_loop(
    upstream: russh::client::Handle<AcceptAnyKey>,
    mut channel: russh::Channel<ClientMsg>,
    mut commands: mpsc::Receiver<UpCmd>,
    mut cancel: oneshot::Receiver<()>,
    client_side: Arc<Mutex<Option<(ChannelId, russh::server::Handle)>>>,
    upload: mpsc::Sender<UploadItem>,
    recording_id: String,
    started: Instant,
) {
    let session = upstream;
    let mut pending: Vec<CryptoVec> = Vec::new();
    loop {
        flush_pending(&client_side, &mut pending).await;
        tokio::select! {
            biased;
            _ = &mut cancel => break,
            command = commands.recv() => {
                let Some(command) = command else { break };
                if !apply_command(&channel, command).await {
                    break;
                }
            }
            message = channel.wait() => {
                match message {
                    Some(ChannelMsg::Data { data }) => {
                        push_chunk(&upload, &recording_id, started, "out", &data).await;
                        pending.push(data);
                    }
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        push_chunk(&upload, &recording_id, started, "err", &data).await;
                        let side = client_side.lock().await.clone();
                        if let Some((id, handle)) = side {
                            let _ = handle.extended_data(id, ext, data).await;
                        }
                    }
                    Some(ChannelMsg::Eof) => {
                        let side = client_side.lock().await.clone();
                        if let Some((id, handle)) = side {
                            let _ = handle.eof(id).await;
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        let side = client_side.lock().await.clone();
                        if let Some((id, handle)) = side {
                            let _ = handle.exit_status_request(id, exit_status).await;
                        }
                    }
                    Some(ChannelMsg::Close) | None => {
                        let side = client_side.lock().await.clone();
                        if let Some((id, handle)) = side {
                            let _ = handle.eof(id).await;
                            let _ = handle.close(id).await;
                        }
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    let _ = channel.eof().await;
    let _ = channel.close().await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "")
        .await;
}

async fn apply_command(channel: &russh::Channel<ClientMsg>, command: UpCmd) -> bool {
    let result = match command {
        UpCmd::Pty {
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            modes,
        } => {
            channel
                .request_pty(false, &term, col_width, row_height, pix_width, pix_height, &modes)
                .await
        }
        UpCmd::Shell => channel.request_shell(false).await,
        UpCmd::Exec(cmd) => channel.exec(false, cmd).await,
        UpCmd::Data(data) => channel.data(data.as_slice()).await,
        UpCmd::Extended { ext, data } => channel.extended_data(ext, data.as_slice()).await,
        UpCmd::Window {
            col_width,
            row_height,
            pix_width,
            pix_height,
        } => channel.window_change(col_width, row_height, pix_width, pix_height).await,
        UpCmd::Eof => channel.eof().await,
        UpCmd::Close => channel.close().await,
    };
    result.is_ok()
}

async fn flush_pending(
    client_side: &Mutex<Option<(ChannelId, russh::server::Handle)>>,
    pending: &mut Vec<CryptoVec>,
) {
    if pending.is_empty() {
        return;
    }
    let side = client_side.lock().await.clone();
    let Some((id, handle)) = side else {
        return;
    };
    for data in pending.drain(..) {
        let _ = handle.data(id, data).await;
    }
}

async fn push_chunk(
    upload: &mpsc::Sender<UploadItem>,
    recording_id: &str,
    started: Instant,
    direction: &str,
    data: &[u8],
) {
    if data.is_empty() {
        return;
    }
    let _ = upload
        .send(UploadItem::Chunk {
            id: recording_id.to_string(),
            t_ms: elapsed_ms(started),
            direction: direction.to_string(),
            data: data.to_vec(),
        })
        .await;
}

fn client_closed(err: &AgentError) -> bool {
    let AgentError::Proxy(text) = err else {
        return false;
    };
    text.contains("early eof")
        || text.contains("Connection closed")
        || text.contains("Disconnected")
        || text.contains("broken pipe")
        || text.contains("Connection reset")
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[async_trait]
impl russh::server::Handler for Bridge {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.to_upstream.is_some() {
            return Ok(Auth::Accept);
        }
        Ok(self.open_upstream(user, password).await)
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(reject_password())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(reject_password())
    }

    async fn auth_keyboard_interactive(
        &mut self,
        user: &str,
        _submethods: &str,
        mut response: Option<russh::server::Response<'async_trait>>,
    ) -> Result<Auth, Self::Error> {
        let Some(response) = response.as_mut() else {
            return Ok(Auth::Partial {
                name: Cow::Borrowed("KeepPAM"),
                instructions: Cow::Borrowed(""),
                prompts: Cow::Owned(vec![(Cow::Borrowed("Password: "), false)]),
            });
        };
        let password = response
            .next()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        if self.to_upstream.is_some() {
            return Ok(Auth::Accept);
        }
        Ok(self.open_upstream(user, &password).await)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<ServerMsg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let mut slot = self.client_side.lock().await;
        if slot.is_some() {
            return Ok(false);
        }
        *slot = Some((channel.id(), session.handle()));
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let ok = self
            .command(UpCmd::Pty {
                term: term.to_string(),
                col_width,
                row_height,
                pix_width,
                pix_height,
                modes: modes.to_vec(),
            })
            .await;
        if ok {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.command(UpCmd::Shell).await {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record("in", data).await;
        if self.command(UpCmd::Exec(data.to_vec())).await {
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record("in", data).await;
        let _ = self.command(UpCmd::Data(data.to_vec())).await;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        _channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.record("in", data).await;
        let _ = self
            .command(UpCmd::Extended {
                ext: code,
                data: data.to_vec(),
            })
            .await;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self
            .command(UpCmd::Window {
                col_width,
                row_height,
                pix_width,
                pix_height,
            })
            .await;
        session.channel_success(channel)?;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self.command(UpCmd::Eof).await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self.command(UpCmd::Close).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_config_block_is_replaced_and_does_not_repeat() {
        let block = ssh_block(
            "\"/opt/endpoint-agent\" proxy --server http://127.0.0.1:8090 --state-dir \"/var/agent\" %h %p",
            Path::new("/var/agent/known_hosts"),
        );
        assert!(!block.contains("%pass"));
        assert!(block.contains("%h %p"));
        let original = "Host example\n    User me\n";
        let once = upsert_block(original, &block);
        assert!(once.contains("Host example"));
        assert_eq!(once.matches(MARK_BEGIN).count(), 1);
        let replaced = block.replace("8090", "8091");
        let twice = upsert_block(&once, &replaced);
        assert!(twice.contains("8091"));
        assert!(!twice.contains("8090"));
        assert_eq!(twice.matches(MARK_BEGIN).count(), 1);
        assert!(twice.contains("User me"));
        assert!(twice.find(MARK_BEGIN).unwrap() < twice.find("Host example").unwrap());
    }

    #[test]
    fn stopping_agent_removes_ssh_redirect() {
        let block = ssh_block(
            "\"/opt/endpoint-agent\" proxy --server http://127.0.0.1:8090 --state-dir \"/var/agent\" %h %p",
            Path::new("/var/agent/known_hosts"),
        );
        let original = "Host example\n    User me\n    StrictHostKeyChecking yes\n";
        let installed = upsert_block(original, &block);
        assert!(installed.contains("ProxyCommand"));
        let cleared = remove_block(&installed);
        assert!(!cleared.contains(MARK_BEGIN));
        assert!(!cleared.contains("ProxyCommand"));
        assert!(cleared.contains("Host example"));
        assert!(cleared.contains("StrictHostKeyChecking yes"));
        assert!(cleared.contains("User me"));
    }

    #[test]
    fn windows_paths_keep_slashes_in_ssh_config() {
        let command = proxy_command(
            Path::new(r"D:\PAM\endpoint-agent.exe"),
            "http://10.0.126.235:8090",
            Path::new(r"C:\ProgramData\KeepPAM\agent"),
            "%h",
            "%p",
        )
        .unwrap();
        assert_eq!(
            command,
            r#""D:/PAM/endpoint-agent.exe" proxy --server http://10.0.126.235:8090 --state-dir "C:/ProgramData/KeepPAM/agent" %h %p"#
        );
        let block = ssh_block(&command, Path::new(r"C:\ProgramData\KeepPAM\agent\known_hosts"));
        assert!(block.contains("UserKnownHostsFile \"C:/ProgramData/KeepPAM/agent/known_hosts\""));
        assert!(!block.contains('\\'));
    }
}
