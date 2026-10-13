mod html;
mod http;
mod store;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use tokio::net::TcpListener;

pub use http::AppState;

pub async fn serve(data_dir: PathBuf, bind: SocketAddr, user: String, password: String) -> anyhow::Result<()> {
    std::fs::create_dir_all(&data_dir).context("каталог данных")?;
    let state = AppState::open(&data_dir, user, password).context("база агентов")?;
    let listener = TcpListener::bind(bind).await.context("адрес сервиса")?;
    let addr = listener.local_addr().context("локальный адрес")?;
    eprintln!("agentd слушает http://{addr}");
    axum::serve(listener, http::router(state))
        .await
        .context("http")?;
    Ok(())
}

pub fn run_from_env() -> anyhow::Result<()> {
    let data_dir = std::env::var("AGENTD_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./data"));
    let bind = parse_addr(
        &std::env::var("AGENTD_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:8090".into()),
    )?;
    let user = std::env::var("AGENTD_OPERATOR_USER").unwrap_or_else(|_| "operator".into());
    let password = std::env::var("AGENTD_OPERATOR_PASSWORD")
        .map_err(|_| anyhow!("задайте AGENTD_OPERATOR_PASSWORD"))?;
    if password.is_empty() {
        return Err(anyhow!("AGENTD_OPERATOR_PASSWORD пуст"));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("runtime")?;
    runtime.block_on(serve(data_dir, bind, user, password))
}

fn parse_addr(value: &str) -> anyhow::Result<SocketAddr> {
    if let Some(port) = value.strip_prefix(':') {
        let port: u16 = port.parse().context("порт AGENTD_HTTP_ADDR")?;
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    value.parse().context("AGENTD_HTTP_ADDR")
}

pub mod testutil {
    use std::path::Path;

    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    use super::http::{router, AppState};

    pub struct TestServer {
        pub base: String,
        shutdown: Option<oneshot::Sender<()>>,
        handle: Option<JoinHandle<()>>,
    }

    impl TestServer {
        pub async fn spawn(data_dir: &Path, user: &str, password: &str) -> anyhow::Result<Self> {
            std::fs::create_dir_all(data_dir)?;
            let state = AppState::open(data_dir, user, password)?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let (tx, rx) = oneshot::channel();
            let handle = tokio::spawn(async move {
                let _ = axum::serve(listener, router(state))
                    .with_graceful_shutdown(async move {
                        let _ = rx.await;
                    })
                    .await;
            });
            tokio::task::yield_now().await;
            Ok(Self {
                base: format!("http://{addr}"),
                shutdown: Some(tx),
                handle: Some(handle),
            })
        }

        pub async fn shutdown(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            if let Some(handle) = self.handle.take() {
                let _ = handle.await;
            }
        }
    }
}
