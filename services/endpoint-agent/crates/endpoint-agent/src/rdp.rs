//! Запись окна mstsc: исходящее TCP клиента RDP и кадры этого окна.

#[cfg(any(windows, test))]
use std::collections::HashMap;

#[cfg(any(windows, test))]
use keeppam_agent_monitor::TcpConnect;

#[cfg(any(windows, test))]
pub(crate) fn is_rdp_process(name: &str) -> bool {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    matches!(base.to_ascii_lowercase().as_str(), "mstsc.exe" | "msrdc.exe")
}

#[cfg(any(windows, test))]
pub(crate) fn choose_rdp(flows: &[TcpConnect]) -> Vec<TcpConnect> {
    let mut by_pid: HashMap<i32, TcpConnect> = HashMap::new();
    for flow in flows {
        if !is_rdp_process(&flow.name) || flow.port == 0 {
            continue;
        }
        match by_pid.get(&flow.pid) {
            Some(current) if current.port == 3389 && flow.port != 3389 => {}
            _ => {
                by_pid.insert(flow.pid, flow.clone());
            }
        }
    }
    let mut out: Vec<_> = by_pid.into_values().collect();
    out.sort_by_key(|flow| flow.pid);
    out
}

#[cfg(windows)]
pub(crate) fn spawn(
    live: std::sync::Arc<std::sync::Mutex<crate::settings::LiveSettings>>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("rdp-capture".into())
        .spawn(move || capture_loop(live))
        .expect("поток записи rdp")
}

#[cfg(windows)]
struct Ctx {
    dir: std::path::PathBuf,
    url: String,
    identity: crate::Identity,
}

#[cfg(windows)]
struct LiveRec {
    id: String,
    address: String,
    port: u16,
    started: std::time::Instant,
    misses: u8,
    last_sent: u64,
    last_jpeg: Vec<u8>,
}

#[cfg(windows)]
fn capture_loop(live: std::sync::Arc<std::sync::Mutex<crate::settings::LiveSettings>>) {
    unsafe { windows_sys::Win32::UI::WindowsAndMessaging::SetProcessDPIAware() };
    let mut sessions: HashMap<i32, LiveRec> = HashMap::new();
    loop {
        if stopped(&live) {
            finish_all(&live, &mut sessions);
            return;
        }
        let Some(ctx) = context(&live) else {
            pause(&live);
            continue;
        };
        let targets = choose_rdp(&keeppam_agent_monitor::established_tcp());
        let seen = targets.iter().map(|flow| flow.pid).collect::<std::collections::HashSet<_>>();
        for target in &targets {
            sync_session(&ctx, &mut sessions, target);
        }
        let stale: Vec<i32> = sessions.keys().copied().filter(|pid| !seen.contains(pid)).collect();
        for pid in stale {
            let done = sessions.get_mut(&pid).map(|session| {
                session.misses = session.misses.saturating_add(1);
                session.misses >= 3
            });
            if done == Some(true) {
                if let Some(session) = sessions.remove(&pid) {
                    end_session(&ctx, &session);
                }
            }
        }
        pause(&live);
    }
}

#[cfg(windows)]
fn sync_session(ctx: &Ctx, sessions: &mut HashMap<i32, LiveRec>, target: &TcpConnect) {
    let Some(jpeg) = capture_pid(target.pid as u32) else {
        if let Some(session) = sessions.get_mut(&target.pid) {
            session.misses = 0;
        }
        return;
    };
    enum Step {
        Skip,
        Chunk { id: String, t_ms: u64 },
        Replace,
        Start,
    }
    let step = if let Some(session) = sessions.get_mut(&target.pid) {
        session.misses = 0;
        if session.address == target.address && session.port == target.port {
            let t_ms = u64::try_from(session.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if session.last_jpeg == jpeg && t_ms.saturating_sub(session.last_sent) < 5_000 {
                Step::Skip
            } else {
                let id = session.id.clone();
                session.last_jpeg = jpeg.clone();
                session.last_sent = t_ms;
                Step::Chunk { id, t_ms }
            }
        } else {
            Step::Replace
        }
    } else {
        Step::Start
    };
    match step {
        Step::Skip => {}
        Step::Chunk { id, t_ms } => {
            crate::upload::submit_chunk(&ctx.dir, &ctx.url, &ctx.identity, &id, t_ms, "frame", &jpeg);
        }
        Step::Replace => {
            if let Some(session) = sessions.remove(&target.pid) {
                end_session(ctx, &session);
            }
            begin(ctx, sessions, target, jpeg);
        }
        Step::Start => begin(ctx, sessions, target, jpeg),
    }
}

#[cfg(windows)]
fn begin(ctx: &Ctx, sessions: &mut HashMap<i32, LiveRec>, target: &TcpConnect, jpeg: Vec<u8>) {
    let id = uuid::Uuid::new_v4().to_string();
    let started_at = unix_now();
    crate::upload::submit_start(
        &ctx.dir,
        &ctx.url,
        &ctx.identity,
        &id,
        &target.address,
        target.port,
        "rdp",
        started_at,
        "rdp",
    );
    crate::upload::submit_chunk(&ctx.dir, &ctx.url, &ctx.identity, &id, 0, "frame", &jpeg);
    note(
        &ctx.dir,
        &format!("start {id} {}:{} pid {}", target.address, target.port, target.pid),
    );
    sessions.insert(
        target.pid,
        LiveRec {
            id,
            address: target.address.clone(),
            port: target.port,
            started: std::time::Instant::now(),
            misses: 0,
            last_sent: 0,
            last_jpeg: jpeg,
        },
    );
}

#[cfg(windows)]
fn end_session(ctx: &Ctx, session: &LiveRec) {
    crate::upload::submit_end(&ctx.dir, &ctx.url, &ctx.identity, &session.id, unix_now());
    note(&ctx.dir, &format!("end {}", session.id));
}

#[cfg(windows)]
fn finish_all(
    live: &std::sync::Arc<std::sync::Mutex<crate::settings::LiveSettings>>,
    sessions: &mut HashMap<i32, LiveRec>,
) {
    let Some(ctx) = context(live) else {
        return;
    };
    for (_, session) in sessions.drain() {
        end_session(&ctx, &session);
    }
}

#[cfg(windows)]
fn context(live: &std::sync::Arc<std::sync::Mutex<crate::settings::LiveSettings>>) -> Option<Ctx> {
    let (dir, url) = {
        let guard = live.lock().expect("настройки");
        (guard.state_dir.clone(), guard.settings.endpoint())
    };
    let identity = crate::LocalState::load(&dir).ok()?.identity?;
    Some(Ctx { dir, url, identity })
}

#[cfg(windows)]
fn stopped(live: &std::sync::Arc<std::sync::Mutex<crate::settings::LiveSettings>>) -> bool {
    live.lock().expect("настройки").stop
}

#[cfg(windows)]
fn pause(live: &std::sync::Arc<std::sync::Mutex<crate::settings::LiveSettings>>) {
    for _ in 0..5 {
        if stopped(live) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(windows)]
fn note(dir: &std::path::Path, line: &str) {
    use std::io::Write;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("rdp.log"))
    else {
        return;
    };
    let _ = writeln!(file, "{line}");
}

#[cfg(windows)]
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(windows)]
#[link(name = "user32")]
extern "system" {
    fn PrintWindow(
        hwnd: windows_sys::Win32::Foundation::HWND,
        hdc: windows_sys::Win32::Graphics::Gdi::HDC,
        flags: u32,
    ) -> windows_sys::Win32::Foundation::BOOL;
}

#[cfg(windows)]
unsafe fn print_window(
    hwnd: windows_sys::Win32::Foundation::HWND,
    hdc: windows_sys::Win32::Graphics::Gdi::HDC,
    flags: u32,
) -> windows_sys::Win32::Foundation::BOOL {
    PrintWindow(hwnd, hdc, flags)
}

#[cfg(windows)]
fn capture_pid(pid: u32) -> Option<Vec<u8>> {
    let hwnd = find_window(pid)?;
    unsafe { grab(hwnd) }
}

#[cfg(windows)]
struct Pick {
    pid: u32,
    hwnd: windows_sys::Win32::Foundation::HWND,
    area: i64,
}

#[cfg(windows)]
unsafe extern "system" fn enum_window(
    hwnd: windows_sys::Win32::Foundation::HWND,
    param: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::BOOL {
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowRect, GetWindowThreadProcessId, IsWindowVisible};
    let pick = &mut *(param as *mut Pick);
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, &mut pid);
    if pid != pick.pid || IsWindowVisible(hwnd) == 0 {
        return 1;
    }
    let mut rect: RECT = std::mem::zeroed();
    if GetWindowRect(hwnd, &mut rect) == 0 {
        return 1;
    }
    let width = (rect.right - rect.left) as i64;
    let height = (rect.bottom - rect.top) as i64;
    if width < 200 || height < 150 {
        return 1;
    }
    let area = width.saturating_mul(height);
    if area > pick.area {
        pick.area = area;
        pick.hwnd = hwnd;
    }
    1
}

#[cfg(windows)]
fn find_window(pid: u32) -> Option<windows_sys::Win32::Foundation::HWND> {
    use windows_sys::Win32::Foundation::LPARAM;
    use windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows;
    let mut pick = Pick {
        pid,
        hwnd: std::ptr::null_mut(),
        area: 0,
    };
    unsafe {
        EnumWindows(Some(enum_window), &mut pick as *mut Pick as LPARAM);
    }
    if pick.hwnd.is_null() {
        None
    } else {
        Some(pick.hwnd)
    }
}

#[cfg(windows)]
unsafe fn grab(hwnd: windows_sys::Win32::Foundation::HWND) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::RECT;
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetWindowDC, ReleaseDC, SelectObject,
        BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::GetWindowRect;
    let mut rect: RECT = std::mem::zeroed();
    if GetWindowRect(hwnd, &mut rect) == 0 {
        return None;
    }
    let width = rect.right.saturating_sub(rect.left);
    let height = rect.bottom.saturating_sub(rect.top);
    let pixels = (width as i64).saturating_mul(height as i64);
    if width < 80 || height < 60 || pixels > 9_000_000 {
        return None;
    }
    let window_dc = GetWindowDC(hwnd);
    if window_dc.is_null() {
        return None;
    }
    let mem = CreateCompatibleDC(window_dc);
    if mem.is_null() {
        ReleaseDC(hwnd, window_dc);
        return None;
    }
    let header = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [windows_sys::Win32::Graphics::Gdi::RGBQUAD {
            rgbBlue: 0,
            rgbGreen: 0,
            rgbRed: 0,
            rgbReserved: 0,
        }],
    };
    let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
    let dib = CreateDIBSection(mem, &header, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
    if dib.is_null() || bits.is_null() {
        if !dib.is_null() {
            DeleteObject(dib);
        }
        DeleteDC(mem);
        ReleaseDC(hwnd, window_dc);
        return None;
    }
    let old = SelectObject(mem, dib);
    if print_window(hwnd, mem, 2) == 0 {
        BitBlt(mem, 0, 0, width, height, window_dc, 0, 0, SRCCOPY);
    }
    let nbytes = (width as usize).saturating_mul(height as usize).saturating_mul(4);
    let bgra = std::slice::from_raw_parts(bits as *const u8, nbytes).to_vec();
    if !old.is_null() {
        SelectObject(mem, old);
    }
    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(hwnd, window_dc);
    let (rgb, dw, dh) = fit_rgb(&bgra, width as u32, height as u32);
    encode_jpeg(&rgb, dw, dh)
}

#[cfg(windows)]
fn fit_rgb(bgra: &[u8], width: u32, height: u32) -> (Vec<u8>, u32, u32) {
    let mut dw = width.max(1);
    let mut dh = height.max(1);
    let max_w = 1280u32;
    let max_h = 720u32;
    if dw > max_w || dh > max_h {
        let scale = (max_w as f64 / dw as f64).min(max_h as f64 / dh as f64);
        dw = ((dw as f64) * scale).round().max(1.0) as u32;
        dh = ((dh as f64) * scale).round().max(1.0) as u32;
    }
    let mut rgb = vec![0u8; (dw as usize) * (dh as usize) * 3];
    for y in 0..dh {
        let sy = (y as u64 * height as u64 / dh as u64) as u32;
        for x in 0..dw {
            let sx = (x as u64 * width as u64 / dw as u64) as u32;
            let i = ((sy as usize) * (width as usize) + sx as usize) * 4;
            let o = ((y as usize) * (dw as usize) + x as usize) * 3;
            if i + 2 < bgra.len() {
                rgb[o] = bgra[i + 2];
                rgb[o + 1] = bgra[i + 1];
                rgb[o + 2] = bgra[i];
            }
        }
    }
    (rgb, dw, dh)
}

#[cfg(windows)]
fn encode_jpeg(rgb: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
    if width == 0 || height == 0 || width > u16::MAX as u32 || height > u16::MAX as u32 {
        return None;
    }
    let mut out = Vec::new();
    jpeg_encoder::Encoder::new(&mut out, 55)
        .encode(rgb, width as u16, height as u16, jpeg_encoder::ColorType::Rgb)
        .ok()?;
    if out.is_empty() || out.len() > 1024 * 1024 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdp_clients_are_mstsc_and_the_store_app() {
        assert!(is_rdp_process("mstsc.exe"));
        assert!(is_rdp_process("Mstsc.EXE"));
        assert!(is_rdp_process(r"C:\Windows\System32\mstsc.exe"));
        assert!(is_rdp_process("msrdc.exe"));
        assert!(!is_rdp_process("ssh.exe"));
        assert!(!is_rdp_process("putty.exe"));
    }

    #[test]
    fn one_recording_per_rdp_process_prefers_port_3389() {
        let flows = vec![
            TcpConnect {
                pid: 4,
                name: "ssh.exe".into(),
                address: "10.0.0.1".into(),
                port: 22,
            },
            TcpConnect {
                pid: 9,
                name: "mstsc.exe".into(),
                address: "10.1.1.8".into(),
                port: 443,
            },
            TcpConnect {
                pid: 9,
                name: "mstsc.exe".into(),
                address: "10.1.1.9".into(),
                port: 3389,
            },
            TcpConnect {
                pid: 12,
                name: "msrdc.exe".into(),
                address: "10.2.2.2".into(),
                port: 3391,
            },
        ];
        let chosen = choose_rdp(&flows);
        assert_eq!(chosen.len(), 2);
        assert_eq!(chosen[0].pid, 9);
        assert_eq!(chosen[0].port, 3389);
        assert_eq!(chosen[0].address, "10.1.1.9");
        assert_eq!(chosen[1].pid, 12);
        assert_eq!(chosen[1].port, 3391);
    }
}
