use std::sync::{Arc, Mutex, OnceLock};

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, SYSTEMTIME, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateBitmap, CreateDIBSection, DeleteObject, GetDC, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
    DIB_RGB_COLORS, RGBQUAD,
};
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_INFO, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DispatchMessageW,
    CreateIconIndirect, GetCursorPos, GetDlgItem, GetDlgItemTextW, GetMessageW, GetSystemMetrics,
    LoadCursorW, LoadIconW, MSG, PostMessageW, SetProcessDPIAware,
    PostQuitMessage, RegisterClassW, SendMessageW, SetForegroundWindow, SetTimer, SetWindowTextW,
    ShowWindow, TrackPopupMenu, TranslateMessage, BS_AUTOCHECKBOX, ES_AUTOHSCROLL, IDC_ARROW,
    ICONINFO, IDI_SHIELD, MF_GRAYED, MF_SEPARATOR, MF_STRING, SM_CXICON, SM_CXSMICON, SW_HIDE, SW_SHOW,
    TPM_RIGHTBUTTON, WM_CLOSE,
    WM_COMMAND, WM_CREATE, WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP,
    WM_TIMER, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_MINIMIZEBOX, WS_SYSMENU, WS_TABSTOP,
    WS_VISIBLE,
};

use crate::settings::{save_dev_settings, LiveSettings, DevSettings};
use crate::state::LocalState;
use crate::{run_supervised, AgentConfig, AgentError};

const TRAY_MSG: u32 = 0x8000 + 20;
const CMD_OPEN: usize = 1;
const CMD_STOP: usize = 2;
const ID_IP: i32 = 101;
const ID_SERVER: i32 = 102;
const ID_PORT: i32 = 103;
const ID_TOKEN: i32 = 104;
const ID_DEV: i32 = 105;
const ID_SAVE: i32 = 106;
const ID_STATUS: i32 = 201;
const ID_TOKEN_INFO: i32 = 202;
const ID_AGENT: i32 = 203;
const BM_GETCHECK: u32 = 240;
const BM_SETCHECK: u32 = 241;
const BST_CHECKED: usize = 1;
const EM_SETREADONLY: u32 = 0x00CF;
const WM_SYSCOMMAND: u32 = 0x0112;
const SC_MINIMIZE: usize = 0xF020;

struct Ui {
    live: Arc<Mutex<LiveSettings>>,
    tray: usize,
    cfg: usize,
}

fn as_hwnd(value: usize) -> HWND {
    value as HWND
}

static UI: OnceLock<Ui> = OnceLock::new();

pub fn run_resident(config: AgentConfig) -> Result<(), AgentError> {
    let mut settings = crate::settings::load_dev_settings(
        &config.state_dir,
        &config.server_url,
        config.enroll_token.as_deref(),
    );
    if server_flag_present() {
        let parsed = DevSettings::from_server_url(&config.server_url, None);
        settings.ip = parsed.ip;
        settings.server = parsed.server;
        settings.port = parsed.port;
    }
    let mut generation = 0u64;
    if let Some(token) = config.enroll_token.as_deref() {
        if token != settings.enroll_token {
            settings.token_changed_at = local_stamp();
        }
        settings.enroll_token = token.to_string();
    }
    let identity = LocalState::load(&config.state_dir).ok().and_then(|state| state.identity);
    if identity.is_none() && !settings.enroll_token.is_empty() {
        generation = 1;
    }
    let _ = save_dev_settings(&config.state_dir, &settings);
    let endpoint = settings.endpoint();
    let hook_dir = config.state_dir.clone();
    let status = match crate::proxy::enable_redirect(&endpoint, &hook_dir, None) {
        Ok(text) => text,
        Err(err) => format!("перехват SSH не включён: {err}"),
    };
    let live = Arc::new(Mutex::new(LiveSettings {
        state_dir: config.state_dir,
        interval: config.interval,
        settings,
        enroll_generation: generation,
        status,
        agent_id: identity.map(|item| item.agent_id).unwrap_or_default(),
        stop: false,
    }));
    let worker_live = Arc::clone(&live);
    let worker = std::thread::Builder::new()
        .name("keeppam-agent".into())
        .spawn(move || run_supervised(worker_live))
        .map_err(|err| AgentError::State(err.to_string()))?;
    let result = unsafe { ui_main(live.clone()) };
    live.lock().expect("настройки").stop = true;
    let _ = worker.join();
    result
}

fn server_flag_present() -> bool {
    std::env::var("AGENT_SERVER_URL").is_ok()
        || std::env::args().skip(1).any(|arg| arg == "--server" || arg.starts_with("--server="))
}

unsafe fn ui_main(live: Arc<Mutex<LiveSettings>>) -> Result<(), AgentError> {
    let console = GetConsoleWindow();
    if !console.is_null() {
        ShowWindow(console, SW_HIDE);
    }
    let instance = GetModuleHandleW(std::ptr::null());
    SetProcessDPIAware();
    let fallback = LoadIconW(std::ptr::null_mut(), IDI_SHIELD);
    let icon = logo_icon(icon_edge(SM_CXICON, 32)).unwrap_or(fallback);
    let tray_icon = logo_icon(icon_edge(SM_CXSMICON, 16)).unwrap_or(icon);
    let tray_class = leak_wide("KeepPAMAgentTray");
    let cfg_class = leak_wide("KeepPAMAgentConfig");
    register_class(tray_class, Some(tray_proc), instance, icon)?;
    register_class(cfg_class, Some(cfg_proc), instance, icon)?;
    let tray = CreateWindowExW(
        0,
        tray_class,
        wide("KeepPAM агент").as_ptr(),
        0,
        0,
        0,
        0,
        0,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        instance,
        std::ptr::null(),
    );
    if tray.is_null() {
        return Err(AgentError::State("не удалось создать окно трея".into()));
    }
    let cfg = CreateWindowExW(
        0,
        cfg_class,
        wide("KeepPAM агент").as_ptr(),
        WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        120,
        120,
        460,
        390,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        instance,
        std::ptr::null(),
    );
    if cfg.is_null() {
        return Err(AgentError::State("не удалось создать окно настроек".into()));
    }
    if UI
        .set(Ui {
            live,
            tray: tray as usize,
            cfg: cfg as usize,
        })
        .is_err()
    {
        return Err(AgentError::State("окно агента уже запущено".into()));
    }
    add_tray_icon(tray, tray_icon)?;
    SetTimer(tray, 1, 1000, None);
    let mut message: MSG = std::mem::zeroed();
    loop {
        let code = GetMessageW(&mut message, std::ptr::null_mut(), 0, 0);
        if code == 0 || code == -1 {
            break;
        }
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    let icon_data = icon_data(tray);
    Shell_NotifyIconW(NIM_DELETE, &icon_data);
    Ok(())
}

unsafe fn register_class(
    name: windows_sys::core::PCWSTR,
    proc: windows_sys::Win32::UI::WindowsAndMessaging::WNDPROC,
    instance: windows_sys::Win32::Foundation::HINSTANCE,
    icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
) -> Result<(), AgentError> {
    let class = WNDCLASSW {
        style: 0,
        lpfnWndProc: proc,
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: instance,
        hIcon: icon,
        hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
        hbrBackground: 16 as windows_sys::Win32::Graphics::Gdi::HBRUSH,
        lpszMenuName: std::ptr::null(),
        lpszClassName: name,
    };
    if RegisterClassW(&class) == 0 {
        return Err(AgentError::State("класс окна не зарегистрирован".into()));
    }
    Ok(())
}

unsafe extern "system" fn tray_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    if msg == TRAY_MSG {
        match lparam as u32 {
            WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_config(),
            WM_RBUTTONUP => show_menu(hwnd),
            _ => {}
        }
        return 0;
    }
    match msg {
        WM_COMMAND => {
            match wparam & 0xffff {
                CMD_OPEN => show_config(),
                CMD_STOP => stop_agent(hwnd),
                _ => {}
            }
            0
        }
        WM_TIMER => {
            refresh_tip(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe extern "system" fn cfg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    match msg {
        WM_CREATE => {
            build_form(hwnd);
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xffff) as i32;
            if id == ID_DEV {
                apply_dev_lock(hwnd);
            }
            if id == ID_SAVE {
                save_form(hwnd);
            }
            0
        }
        WM_SYSCOMMAND if (wparam & 0xFFF0) == SC_MINIMIZE => {
            ShowWindow(hwnd, SW_HIDE);
            0
        }
        WM_CLOSE => {
            ShowWindow(hwnd, SW_HIDE);
            0
        }
        WM_TIMER => {
            paint_status(hwnd);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn build_form(parent: HWND) {
    let instance = GetModuleHandleW(std::ptr::null());
    labeled(parent, instance, "IP", 16, ID_IP);
    labeled(parent, instance, "Сервер", 56, ID_SERVER);
    labeled(parent, instance, "Порт", 96, ID_PORT);
    labeled(parent, instance, "Токен", 136, ID_TOKEN);
    CreateWindowExW(
        0,
        wide("BUTTON").as_ptr(),
        wide("Режим разработки").as_ptr(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32,
        16,
        184,
        220,
        24,
        parent,
        ID_DEV as _,
        instance,
        std::ptr::null(),
    );
    CreateWindowExW(
        0,
        wide("BUTTON").as_ptr(),
        wide("Сохранить").as_ptr(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        16,
        216,
        120,
        28,
        parent,
        ID_SAVE as _,
        instance,
        std::ptr::null(),
    );
    status_line(parent, instance, 256, ID_STATUS);
    status_line(parent, instance, 284, ID_TOKEN_INFO);
    status_line(parent, instance, 312, ID_AGENT);
    SetTimer(parent, 2, 1000, None);
}

unsafe fn labeled(
    parent: HWND,
    instance: windows_sys::Win32::Foundation::HINSTANCE,
    title: &str,
    y: i32,
    id: i32,
) {
    CreateWindowExW(
        0,
        wide("STATIC").as_ptr(),
        wide(title).as_ptr(),
        WS_CHILD | WS_VISIBLE,
        16,
        y,
        90,
        22,
        parent,
        std::ptr::null_mut(),
        instance,
        std::ptr::null(),
    );
    CreateWindowExW(
        0,
        wide("EDIT").as_ptr(),
        std::ptr::null(),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32,
        110,
        y - 2,
        310,
        24,
        parent,
        id as _,
        instance,
        std::ptr::null(),
    );
}

unsafe fn status_line(parent: HWND, instance: windows_sys::Win32::Foundation::HINSTANCE, y: i32, id: i32) {
    CreateWindowExW(
        0,
        wide("STATIC").as_ptr(),
        std::ptr::null(),
        WS_CHILD | WS_VISIBLE,
        16,
        y,
        410,
        22,
        parent,
        id as _,
        instance,
        std::ptr::null(),
    );
}

unsafe fn show_config() {
    let Some(ui) = UI.get() else { return };
    let cfg = as_hwnd(ui.cfg);
    fill_form(cfg);
    ShowWindow(cfg, SW_SHOW);
    SetForegroundWindow(cfg);
}

unsafe fn show_menu(hwnd: HWND) {
    let Some(ui) = UI.get() else { return };
    let (token_line, changed) = {
        let guard = ui.live.lock().expect("настройки");
        let token = if guard.settings.enroll_token.is_empty() {
            "Токен не задан".to_string()
        } else if guard.settings.token_changed_at.is_empty() {
            "Токен задан".to_string()
        } else {
            format!("Токен изменён в {}", guard.settings.token_changed_at)
        };
        (token, guard.settings.token_changed_at.clone())
    };
    let _ = changed;
    let menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, CMD_OPEN, wide("Конфигурация").as_ptr());
    AppendMenuW(menu, MF_GRAYED, 3, wide(&token_line).as_ptr());
    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(menu, MF_STRING, CMD_STOP, wide("Остановить агент").as_ptr());
    let mut point = POINT { x: 0, y: 0 };
    GetCursorPos(&mut point);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, std::ptr::null());
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

unsafe fn stop_agent(hwnd: HWND) {
    match crate::proxy::disable_redirect() {
        Ok(()) => {
            if let Some(ui) = UI.get() {
                ui.live.lock().expect("настройки").stop = true;
            }
            let mut icon_data = icon_data(hwnd);
            Shell_NotifyIconW(NIM_DELETE, &mut icon_data);
            PostQuitMessage(0);
        }
        Err(err) => {
            let text = err.to_string();
            if let Some(ui) = UI.get() {
                ui.live.lock().expect("настройки").status = text.clone();
            }
            notify_info(hwnd, "Агент не остановлен", &text);
        }
    }
}

unsafe fn fill_form(hwnd: HWND) {
    let Some(ui) = UI.get() else { return };
    let settings = ui.live.lock().expect("настройки").settings.clone();
    set_text(GetDlgItem(hwnd, ID_IP), &settings.ip);
    set_text(GetDlgItem(hwnd, ID_SERVER), &settings.server);
    set_text(GetDlgItem(hwnd, ID_PORT), &settings.port.to_string());
    set_text(GetDlgItem(hwnd, ID_TOKEN), &settings.enroll_token);
    SendMessageW(
        GetDlgItem(hwnd, ID_DEV),
        BM_SETCHECK,
        if settings.dev_mode { BST_CHECKED } else { 0 },
        0,
    );
    apply_dev_lock(hwnd);
    paint_status(hwnd);
}

unsafe fn apply_dev_lock(hwnd: HWND) {
    let dev = SendMessageW(GetDlgItem(hwnd, ID_DEV), BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
    for id in [ID_IP, ID_SERVER, ID_PORT, ID_TOKEN] {
        SendMessageW(GetDlgItem(hwnd, id), EM_SETREADONLY, (!dev) as usize, 0);
    }
}

unsafe fn save_form(hwnd: HWND) {
    let Some(ui) = UI.get() else { return };
    let dev_mode = SendMessageW(GetDlgItem(hwnd, ID_DEV), BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
    let mut edited = DevSettings {
        ip: control_text(hwnd, ID_IP),
        server: control_text(hwnd, ID_SERVER),
        port: control_text(hwnd, ID_PORT).parse().unwrap_or(0),
        enroll_token: control_text(hwnd, ID_TOKEN),
        dev_mode,
        token_changed_at: local_stamp(),
    };
    let token_changed = {
        let mut guard = ui.live.lock().expect("настройки");
        let changed = guard.settings.apply_edit(edited.clone());
        if changed {
            guard.enroll_generation = guard.enroll_generation.saturating_add(1);
            guard.status = format!("токен изменён в {}", guard.settings.token_changed_at);
        } else if dev_mode {
            guard.status = format!("конфигурация сохранена: {}", guard.settings.endpoint());
        } else {
            guard.status = "режим разработки выключен, поля не изменены".into();
        }
        edited = guard.settings.clone();
        let _ = save_dev_settings(&guard.state_dir, &guard.settings);
        let dir = guard.state_dir.clone();
        let endpoint = guard.settings.endpoint();
        let base = guard.status.clone();
        (changed, dir, endpoint, base)
    };
    let (token_changed, dir, endpoint, base) = token_changed;
    {
        let mut guard = ui.live.lock().expect("настройки");
        guard.status = match crate::proxy::enable_redirect(&endpoint, &dir, None) {
            Ok(text) => format!("{base}. {text}"),
            Err(err) => format!("{base}. перехват не обновлён: {err}"),
        };
    }
    fill_form(hwnd);
    if token_changed {
        notify_token(as_hwnd(ui.tray), &edited.enroll_token, &edited.token_changed_at);
    }
    refresh_tip(as_hwnd(ui.tray));
}

unsafe fn paint_status(hwnd: HWND) {
    let Some(ui) = UI.get() else { return };
    let guard = ui.live.lock().expect("настройки");
    let token_line = if guard.settings.token_changed_at.is_empty() {
        "Токен ещё не менялся".to_string()
    } else {
        format!("Токен изменён в {}", guard.settings.token_changed_at)
    };
    let agent_line = if guard.agent_id.is_empty() {
        "Агент не зачислен".to_string()
    } else {
        format!("Агент {}", guard.agent_id)
    };
    set_text(GetDlgItem(hwnd, ID_STATUS), &guard.status);
    set_text(GetDlgItem(hwnd, ID_TOKEN_INFO), &token_line);
    set_text(GetDlgItem(hwnd, ID_AGENT), &agent_line);
}

unsafe fn refresh_tip(hwnd: HWND) {
    let Some(ui) = UI.get() else { return };
    let guard = ui.live.lock().expect("настройки");
    let tip = if guard.settings.token_changed_at.is_empty() {
        format!("KeepPAM агент. {}", guard.status)
    } else {
        format!("KeepPAM агент. Токен изменён в {}", guard.settings.token_changed_at)
    };
    let mut data = icon_data(hwnd);
    data.uFlags = NIF_TIP;
    write_wide(&mut data.szTip, &tip);
    Shell_NotifyIconW(NIM_MODIFY, &data);
}

unsafe fn notify_info(hwnd: HWND, title: &str, body: &str) {
    let mut data = icon_data(hwnd);
    data.uFlags = NIF_INFO;
    data.dwInfoFlags = NIIF_INFO;
    write_wide(&mut data.szInfoTitle, title);
    write_wide(&mut data.szInfo, body);
    Shell_NotifyIconW(NIM_MODIFY, &data);
}

unsafe fn notify_token(hwnd: HWND, token: &str, stamp: &str) {
    let mut data = icon_data(hwnd);
    data.uFlags = NIF_INFO;
    data.dwInfoFlags = NIIF_INFO;
    write_wide(&mut data.szInfoTitle, "Токен изменён");
    let body = if token.is_empty() {
        format!("Токен очищен в {stamp}")
    } else {
        format!("{stamp}: {token}")
    };
    write_wide(&mut data.szInfo, &body);
    Shell_NotifyIconW(NIM_MODIFY, &data);
}

unsafe fn add_tray_icon(hwnd: HWND, icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON) -> Result<(), AgentError> {
    let mut data = icon_data(hwnd);
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    data.uCallbackMessage = TRAY_MSG;
    data.hIcon = icon;
    write_wide(&mut data.szTip, "KeepPAM агент");
    if Shell_NotifyIconW(NIM_ADD, &data) == 0 {
        return Err(AgentError::State("значок трея не добавлен".into()));
    }
    Ok(())
}

unsafe fn icon_data(hwnd: HWND) -> NOTIFYICONDATAW {
    let mut data: NOTIFYICONDATAW = std::mem::zeroed();
    data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = 1;
    data
}

unsafe fn control_text(parent: HWND, id: i32) -> String {
    let hwnd = GetDlgItem(parent, id);
    let mut buf = [0u16; 512];
    let n = GetDlgItemTextW(parent, id, buf.as_mut_ptr(), buf.len() as i32);
    let _ = hwnd;
    String::from_utf16_lossy(&buf[..n as usize]).trim().to_string()
}

unsafe fn set_text(hwnd: HWND, text: &str) {
    if hwnd.is_null() {
        return;
    }
    let value = wide(text);
    SetWindowTextW(hwnd, value.as_ptr());
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn leak_wide(text: &str) -> windows_sys::core::PCWSTR {
    let leaked = Box::leak(wide(text).into_boxed_slice());
    leaked.as_ptr()
}

fn write_wide(dest: &mut [u16], text: &str) {
    dest.fill(0);
    for (index, unit) in text.encode_utf16().take(dest.len().saturating_sub(1)).enumerate() {
        dest[index] = unit;
    }
}

const LOGO_PNG: &[u8] = include_bytes!("../../../../../KeepCheck-logo.png");

fn icon_edge(metric: i32, fallback: i32) -> i32 {
    let value = unsafe { GetSystemMetrics(metric) };
    if value > 0 {
        value
    } else {
        fallback
    }
}

fn logo_icon(edge: i32) -> Option<windows_sys::Win32::UI::WindowsAndMessaging::HICON> {
    let edge = edge.max(1) as u32;
    let (width, height, pixels) = decode_logo()?;
    let scaled = downscale(&pixels, width, height, edge, edge);
    unsafe { hicon_from_rgba(&scaled, edge) }
}

fn decode_logo() -> Option<(u32, u32, Vec<u8>)> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(LOGO_PNG));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    let data = &buf[..info.buffer_size()];
    let rgba = match info.color_type {
        png::ColorType::Rgba => data.to_vec(),
        png::ColorType::Rgb => {
            let mut out = Vec::with_capacity(data.len() / 3 * 4);
            for pixel in data.chunks_exact(3) {
                out.extend_from_slice(&[pixel[0], pixel[1], pixel[2], 255]);
            }
            out
        }
        _ => return None,
    };
    if rgba.len() != info.width as usize * info.height as usize * 4 {
        return None;
    }
    Some((info.width, info.height, rgba))
}

fn downscale(src: &[u8], src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Vec<u8> {
    let mut out = vec![0u8; dst_w as usize * dst_h as usize * 4];
    for y in 0..dst_h {
        let y0 = y * src_h / dst_h;
        let y1 = ((y + 1) * src_h / dst_h).max(y0 + 1);
        for x in 0..dst_w {
            let x0 = x * src_w / dst_w;
            let x1 = ((x + 1) * src_w / dst_w).max(x0 + 1);
            let mut red = 0u64;
            let mut green = 0u64;
            let mut blue = 0u64;
            let mut alpha = 0u64;
            let mut count = 0u64;
            for yy in y0..y1 {
                for xx in x0..x1 {
                    let index = ((yy * src_w + xx) * 4) as usize;
                    let pixel_alpha = src[index + 3] as u64;
                    red += src[index] as u64 * pixel_alpha;
                    green += src[index + 1] as u64 * pixel_alpha;
                    blue += src[index + 2] as u64 * pixel_alpha;
                    alpha += pixel_alpha;
                    count += 1;
                }
            }
            let index = ((y * dst_w + x) * 4) as usize;
            if alpha == 0 {
                continue;
            }
            out[index] = (red / alpha) as u8;
            out[index + 1] = (green / alpha) as u8;
            out[index + 2] = (blue / alpha) as u8;
            out[index + 3] = (alpha / count) as u8;
        }
    }
    out
}

unsafe fn hicon_from_rgba(
    rgba: &[u8],
    edge: u32,
) -> Option<windows_sys::Win32::UI::WindowsAndMessaging::HICON> {
    let mut bgra = Vec::with_capacity(rgba.len());
    for pixel in rgba.chunks_exact(4) {
        let alpha = pixel[3] as u32;
        bgra.extend_from_slice(&[
            (pixel[2] as u32 * alpha / 255) as u8,
            (pixel[1] as u32 * alpha / 255) as u8,
            (pixel[0] as u32 * alpha / 255) as u8,
            pixel[3],
        ]);
    }
    let header = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: edge as i32,
            biHeight: -(edge as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            biSizeImage: bgra.len() as u32,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [RGBQUAD {
            rgbBlue: 0,
            rgbGreen: 0,
            rgbRed: 0,
            rgbReserved: 0,
        }],
    };
    let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
    let dc = GetDC(std::ptr::null_mut());
    let color = CreateDIBSection(
        dc,
        &header,
        DIB_RGB_COLORS,
        &mut bits,
        std::ptr::null_mut(),
        0,
    );
    ReleaseDC(std::ptr::null_mut(), dc);
    if color.is_null() || bits.is_null() {
        if !color.is_null() {
            DeleteObject(color);
        }
        return None;
    }
    std::ptr::copy_nonoverlapping(bgra.as_ptr(), bits as *mut u8, bgra.len());
    let mask = CreateBitmap(edge as i32, edge as i32, 1, 1, std::ptr::null());
    if mask.is_null() {
        DeleteObject(color);
        return None;
    }
    let info = ICONINFO {
        fIcon: 1,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: mask,
        hbmColor: color,
    };
    let icon = CreateIconIndirect(&info);
    DeleteObject(color);
    DeleteObject(mask);
    if icon.is_null() {
        None
    } else {
        Some(icon)
    }
}

fn local_stamp() -> String {
    let mut time = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    unsafe { GetLocalTime(&mut time) };
    format!("{:02}:{:02}:{:02}", time.wHour, time.wMinute, time.wSecond)
}
