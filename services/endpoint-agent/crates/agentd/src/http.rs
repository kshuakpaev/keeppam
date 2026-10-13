use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use keeppam_agent_protocol::{
    EnrollRequest, EnrollResponse, EventsRequest, EventsResponse, HeartbeatRequest, HeartbeatResponse,
    RecordingAck, RecordingChunk, RecordingEnd, RecordingStart,
};
use serde::Deserialize;

use crate::html::{self, esc};
use crate::store::{now_unix, Store, StoreError};

#[derive(Clone)]
pub struct AppState {
    store: Arc<Mutex<Store>>,
    sessions: Arc<Mutex<HashMap<String, i64>>>,
    operator_user: String,
    operator_password: String,
    downloads_dir: std::path::PathBuf,
}

impl AppState {
    pub fn open(
        data_dir: &std::path::Path,
        operator_user: impl Into<String>,
        operator_password: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let store = Store::open(&data_dir.join("agentd.sqlite"))?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            operator_user: operator_user.into(),
            operator_password: operator_password.into(),
            downloads_dir: std::env::var("AGENTD_DOWNLOADS_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("/usr/share/keeppam-agent/downloads")),
        })
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/agents", get(agents_page))
        .route("/policy", get(policy_page).post(policy_save))
        .route("/events", get(events_page))
        .route("/downloads", get(downloads_page))
        .route("/downloads/:id", get(download_file))
        .route("/help", get(help_page))
        .route("/recordings", get(recordings_page))
        .route("/recordings/:id", get(recording_page))
        .route("/recordings/:id/frame/:index", get(recording_frame))
        .route("/enrollment", post(enrollment_create))
        .route("/healthz", get(health))
        .route("/v1/enroll", post(enroll))
        .route("/v1/agents/:id/heartbeat", post(heartbeat))
        .route("/v1/agents/:id/policy", get(policy_get))
        .route("/v1/agents/:id/events", post(events_post))
        .route("/v1/agents/:id/recordings", post(recording_open))
        .route(
            "/v1/agents/:id/recordings/:recording_id/chunks",
            post(recording_chunk),
        )
        .route(
            "/v1/agents/:id/recordings/:recording_id/end",
            post(recording_end),
        )
        .with_state(state)
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct PolicyForm {
    targets: String,
    gateways: String,
    #[serde(default)]
    expires_at: String,
}

async fn health() -> &'static str {
    "ok"
}

async fn root(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    if authorized(&state, &headers) {
        redirect("/agents", None)
    } else {
        page(html::login_page(None))
    }
}

async fn login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response<Body> {
    if form.username != state.operator_user || !secrets_equal(&form.password, &state.operator_password) {
        return page(html::login_page(Some("Неверное имя или пароль.")));
    }
    let token = random_hex();
    let expires = now_unix() + 12 * 60 * 60;
    state
        .sessions
        .lock()
        .expect("sessions")
        .insert(token.clone(), expires);
    redirect(
        "/agents",
        Some(&format!(
            "agentd_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200"
        )),
    )
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    if let Some(token) = session_token(&headers) {
        state.sessions.lock().expect("sessions").remove(&token);
    }
    redirect(
        "/",
        Some("agentd_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"),
    )
}

async fn downloads_page(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    page(html::downloads_page(&html::agent_packages(&state.downloads_dir)))
}

async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let Some(package) = html::agent_packages(&state.downloads_dir)
        .into_iter()
        .find(|package| package.id == id && package.size.is_some())
    else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("файл не найден"))
            .expect("text response");
    };
    let path = state.downloads_dir.join(package.filename);
    match std::fs::read(&path) {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", package.filename),
            )
            .body(Body::from(bytes))
            .expect("file response"),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("файл не найден"))
            .expect("text response"),
    }
}

async fn help_page(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("127.0.0.1:8090");
    page(html::help_page(&format!("http://{host}")))
}

async fn agents_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let agents = state.store.lock().expect("store").list_agents();
    match agents {
        Ok(agents) => page(html::agents_page(&agents, query.get("token").map(String::as_str))),
        Err(err) => page(html::agents_page(&[], None) + &esc(&err.to_string())),
    }
}

async fn enrollment_create(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let token = {
        let mut store = state.store.lock().expect("store");
        store.create_enrollment_token(now_unix())
    };
    match token {
        Ok(token) => redirect(&format!("/agents?token={token}"), None),
        Err(err) => page(format!("<p class=\"error\">{}</p>", esc(&err.to_string()))),
    }
}

async fn policy_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let policy = state.store.lock().expect("store").signed_policy();
    match policy {
        Ok(signed) => page(html::policy_page(
            signed.as_ref().map(|item| &item.policy),
            None,
            query.get("saved").map(String::as_str) == Some("1"),
        )),
        Err(err) => page(html::policy_page(None, Some(&err.to_string()), false)),
    }
}

async fn policy_save(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<PolicyForm>,
) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let parsed = match html::parse_policy_form(&form.targets, &form.gateways, &form.expires_at) {
        Ok(policy) => policy,
        Err(err) => return page(html::policy_page(None, Some(&err), false)),
    };
    let saved = {
        let mut store = state.store.lock().expect("store");
        store.publish(parsed, now_unix())
    };
    match saved {
        Ok(_) => redirect("/policy?saved=1", None),
        Err(err) => page(html::policy_page(None, Some(&err.to_string()), false)),
    }
}

async fn events_page(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let events = state.store.lock().expect("store").list_events();
    match events {
        Ok(events) => page(html::events_page(&events)),
        Err(err) => page(format!("<p class=\"error\">{}</p>", esc(&err.to_string()))),
    }
}

async fn recordings_page(State(state): State<AppState>, headers: HeaderMap) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let rows = state.store.lock().expect("store").list_recordings();
    match rows {
        Ok(rows) => page(html::recordings_page(&rows)),
        Err(err) => page(format!("<p class=\"error\">{}</p>", esc(&err.to_string()))),
    }
}

async fn recording_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response<Body> {
    if !authorized(&state, &headers) {
        return redirect("/", None);
    }
    let view = state.store.lock().expect("store").recording(&id);
    match view {
        Ok(Some(view)) => page(html::replay_page(&view.row, &view.frames, view.truncated)),
        Ok(None) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(html::replay_missing()))
            .expect("html response"),
        Err(err) => page(format!("<p class=\"error\">{}</p>", esc(&err.to_string()))),
    }
}

async fn recording_frame(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, index)): Path<(String, u32)>,
) -> Response<Body> {
    if !authorized(&state, &headers) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
            .expect("empty response");
    }
    let frame = state.store.lock().expect("store").recording_frame(&id, index);
    match frame {
        Ok(Some(bytes)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "image/jpeg")
            .header(header::CACHE_CONTROL, "private, max-age=86400")
            .body(Body::from(bytes))
            .expect("jpeg response"),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .expect("empty response"),
    }
}

async fn recording_open(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RecordingStart>,
) -> Result<Json<RecordingAck>, ApiError> {
    let secret = bearer(&headers).ok_or(ApiError::unauthorized())?;
    let mut store = state.store.lock().expect("store");
    store.authorize(&id, &secret)?;
    store.open_recording(&id, &body, now_unix())?;
    Ok(Json(RecordingAck { ok: true }))
}

async fn recording_chunk(
    State(state): State<AppState>,
    Path((id, recording_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RecordingChunk>,
) -> Result<Json<RecordingAck>, ApiError> {
    let secret = bearer(&headers).ok_or(ApiError::unauthorized())?;
    let data = STANDARD
        .decode(body.data.trim().as_bytes())
        .map_err(|_| ApiError::bad_request("фрагмент не в base64"))?;
    let mut store = state.store.lock().expect("store");
    store.authorize(&id, &secret)?;
    store.add_chunk(&id, &recording_id, body.t_ms, &body.direction, &data)?;
    Ok(Json(RecordingAck { ok: true }))
}

async fn recording_end(
    State(state): State<AppState>,
    Path((id, recording_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<RecordingEnd>,
) -> Result<Json<RecordingAck>, ApiError> {
    let secret = bearer(&headers).ok_or(ApiError::unauthorized())?;
    let mut store = state.store.lock().expect("store");
    store.authorize(&id, &secret)?;
    store.finish_recording(&id, &recording_id, body.ended_at, now_unix())?;
    Ok(Json(RecordingAck { ok: true }))
}

async fn enroll(
    State(state): State<AppState>,
    Json(body): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    if body.token.trim().is_empty() || body.hostname.trim().is_empty() {
        return Err(ApiError::bad_request("пустой запрос зачисления"));
    }
    let mut store = state.store.lock().expect("store");
    store
        .enroll(&body.token, &body.hostname, &body.version, now_unix())
        .map(Json)
        .map_err(ApiError::from)
}

async fn heartbeat(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let secret = bearer(&headers).ok_or(ApiError::unauthorized())?;
    let mut store = state.store.lock().expect("store");
    store.authorize(&id, &secret)?;
    let policy_version = store.heartbeat(&id, &body.hostname, &body.version, now_unix())?;
    Ok(Json(HeartbeatResponse {
        ok: true,
        policy_version,
    }))
}

async fn policy_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<keeppam_agent_protocol::SignedPolicy>, ApiError> {
    let secret = bearer(&headers).ok_or(ApiError::unauthorized())?;
    let store = state.store.lock().expect("store");
    store.authorize(&id, &secret)?;
    store
        .signed_policy()?
        .map(Json)
        .ok_or(ApiError::not_found("политики ещё нет"))
}

async fn events_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EventsRequest>,
) -> Result<Json<EventsResponse>, ApiError> {
    let secret = bearer(&headers).ok_or(ApiError::unauthorized())?;
    let mut store = state.store.lock().expect("store");
    store.authorize(&id, &secret)?;
    let accepted = body.events.len();
    store.insert_events(&id, &body.events, now_unix())?;
    Ok(Json(EventsResponse { accepted }))
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".into(),
        }
    }

    fn not_found(message: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::EnrollmentRejected | StoreError::Unauthorized => Self::unauthorized(),
            StoreError::NotFound => Self::not_found("запись не найдена"),
            StoreError::BadInput(message) => Self::bad_request(&message),
            StoreError::Protocol(err) => Self::bad_request(&err.to_string()),
            StoreError::Sqlite(_) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "store".into(),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, Json(body)).into_response()
    }
}

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = session_token(headers) else {
        return false;
    };
    let now = now_unix();
    let mut sessions = state.sessions.lock().expect("sessions");
    sessions.retain(|_, expiry| *expiry > now);
    sessions.get(&token).copied().unwrap_or(0) > now
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in value.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("agentd_session=") {
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn secrets_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn random_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn page(body: String) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .expect("html response")
}

fn redirect(location: &str, set_cookie: Option<&str>) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store");
    if let Some(cookie) = set_cookie {
        builder = builder.header(header::SET_COOKIE, cookie);
    }
    builder.body(Body::empty()).expect("redirect")
}
