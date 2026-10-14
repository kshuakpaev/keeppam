use keeppam_agent_protocol::{Decision, Gateway, Mode, Policy, ProtectedTarget};
use serde::Serialize;

use crate::store::{AgentRow, EventRow, RecordingFrame, RecordingRow};

pub fn parse_policy_form(targets: &str, gateways: &str, expires_at: &str) -> Result<Policy, String> {
    let mut protected_targets = Vec::new();
    for (index, line) in targets.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('|').map(str::trim).collect();
        if parts.len() != 3 {
            return Err(format!(
                "строка {}: ожидается id | адреса | порты",
                index + 1
            ));
        }
        let addresses = split_csv(parts[1]);
        let ports = parse_ports(parts[2]).map_err(|err| format!("строка {}: {err}", index + 1))?;
        if parts[0].is_empty() || addresses.is_empty() || ports.is_empty() {
            return Err(format!("строка {}: пустое поле", index + 1));
        }
        protected_targets.push(ProtectedTarget {
            id: parts[0].to_string(),
            addresses,
            ports,
        });
    }
    let mut allowed_gateways = Vec::new();
    for (index, line) in gateways.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('|').map(str::trim).collect();
        if parts.len() != 2 {
            return Err(format!(
                "шлюз, строка {}: ожидается адрес | порты",
                index + 1
            ));
        }
        let ports = parse_ports(parts[1]).map_err(|err| format!("шлюз, строка {}: {err}", index + 1))?;
        if parts[0].is_empty() || ports.is_empty() {
            return Err(format!("шлюз, строка {}: пустое поле", index + 1));
        }
        allowed_gateways.push(Gateway {
            address: parts[0].to_string(),
            ports,
        });
    }
    let expires_at = if expires_at.trim().is_empty() {
        None
    } else {
        Some(
            expires_at
                .trim()
                .parse::<i64>()
                .map_err(|_| "срок действия должен быть unix-временем".to_string())?,
        )
    };
    Ok(Policy {
        version: 0,
        mode: Mode::Audit,
        expires_at,
        protected_targets,
        allowed_gateways,
    })
}

pub fn format_targets(policy: &Policy) -> String {
    policy
        .protected_targets
        .iter()
        .map(|target| {
            format!(
                "{} | {} | {}",
                target.id,
                target.addresses.join(","),
                join_ports(&target.ports)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn format_gateways(policy: &Policy) -> String {
    policy
        .allowed_gateways
        .iter()
        .map(|gateway| format!("{} | {}", gateway.address, join_ports(&gateway.ports)))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn login_page(error: Option<&str>) -> String {
    let error = error
        .map(|text| format!("<p class=\"error\">{}</p>", esc(text)))
        .unwrap_or_default();
    layout(
        "Вход",
        &format!(
            r#"<h1>Вход оператора</h1>
<p class="lead">Учётная запись этого сервиса. Пользователи KeepPAM сюда не входят.</p>
{error}
<form method="post" action="/login">
<label>Имя<input name="username" autocomplete="username" required></label>
<label>Пароль<input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Войти</button>
</form>"#
        ),
        false,
    )
}

pub fn agents_page(agents: &[AgentRow], token: Option<&str>) -> String {
    let token_block = token
        .map(|value| {
            format!(
                r#"<section class="notice"><h2>Токен зачисления</h2>
<p>Скопируйте его сейчас. Повторно он не показывается и действует один раз.</p>
<code id="enrollment-token">{}</code></section>"#,
                esc(value)
            )
        })
        .unwrap_or_default();
    let rows = if agents.is_empty() {
        r#"<p id="agent-count">Агенты ещё не зачислены.</p>"#.to_string()
    } else {
        let body = agents
            .iter()
            .map(|agent| {
                format!(
                    r#"<tr>
<td><code>{}</code></td>
<td class="hostname">{}</td>
<td>{}</td>
<td>{}</td>
</tr>"#,
                    esc(&agent.agent_id),
                    esc(&agent.hostname),
                    esc(&agent.version),
                    esc(&format_unix(agent.last_seen.unwrap_or(0)))
                )
            })
            .collect::<String>();
        format!(
            r#"<p id="agent-count">Агентов: {}</p>
<table>
<thead><tr><th>Идентификатор</th><th>Имя</th><th>Версия</th><th>Последний сигнал</th></tr></thead>
<tbody>{body}</tbody>
</table>"#,
            agents.len()
        )
    };
    layout(
        "Агенты",
        &format!(
            r#"<h1>Агенты</h1>
{token_block}
<form method="post" action="/enrollment">
<button type="submit">Выпустить токен зачисления</button>
</form>
{rows}"#
        ),
        true,
    )
}

pub fn policy_page(policy: Option<&Policy>, error: Option<&str>, saved: bool) -> String {
    let (targets, gateways, expires, version) = match policy {
        Some(policy) => (
            esc(&format_targets(policy)),
            esc(&format_gateways(policy)),
            esc(
                &policy
                    .expires_at
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
            ),
            format!(r#"<p id="policy-version">Версия {}</p>"#, policy.version),
        ),
        None => (String::new(), String::new(), String::new(), String::new()),
    };
    let error = error
        .map(|text| format!(r#"<p class="error" id="policy-error">{}</p>"#, esc(text)))
        .unwrap_or_default();
    let saved = if saved {
        r#"<p class="notice" id="policy-saved">Политика сохранена и подписана.</p>"#
    } else {
        ""
    };
    layout(
        "Политика",
        &format!(
            r#"<h1>Политика</h1>
<p class="lead">Режим этого среза — audit. Сервис считает решение и пишет его в событие. Сетевые фильтры не ставятся.</p>
{version}{saved}{error}
<form method="post" action="/policy">
<label>Защищённые цели
<textarea name="targets" rows="8" placeholder="linux-prod-01 | 10.10.10.20/32 | 22,23">{targets}</textarea>
</label>
<p class="hint">Строка: id | адреса через запятую | порты через запятую. Адрес может быть IP или CIDR.</p>
<label>Разрешённые шлюзы
<textarea name="gateways" rows="5" placeholder="10.10.10.5 | 2222,2323">{gateways}</textarea>
</label>
<p class="hint">Строка: точный IP | порты. Весь трафик на адрес шлюза не разрешается.</p>
<label>Срок действия, unix UTC
<input name="expires_at" value="{expires}" placeholder="пусто — бессрочно">
</label>
<button type="submit">Подписать и сохранить</button>
</form>"#
        ),
        true,
    )
}

pub fn events_page(events: &[EventRow]) -> String {
    let body = if events.is_empty() {
        r#"<p id="event-count">Событий пока нет.</p>"#.to_string()
    } else {
        let rows = events
            .iter()
            .map(|row| {
                let process = row
                    .event
                    .process
                    .as_ref()
                    .map(|process| format!("{} ({})", process.name, process.pid))
                    .unwrap_or_else(|| "—".into());
                let destination = row
                    .event
                    .destination
                    .as_ref()
                    .map(|dest| format!("{}:{}", dest.address, dest.port))
                    .unwrap_or_else(|| "—".into());
                format!(
                    r#"<tr class="event" data-decision="{}">
<td>{}</td>
<td><code>{}</code></td>
<td>{}</td>
<td>{}</td>
<td>{}</td>
<td>{}</td>
</tr>"#,
                    decision_code(row.event.decision.as_ref()),
                    esc(&format_unix(row.received_at)),
                    esc(&short_id(&row.agent_id)),
                    esc(&row.event.event_type),
                    esc(&process),
                    esc(&destination),
                    esc(&decision_label(row.event.decision.as_ref()))
                )
            })
            .collect::<String>();
        format!(
            r#"<p id="event-count">Событий: {}</p>
<table>
<thead><tr><th>Время</th><th>Агент</th><th>Тип</th><th>Процесс</th><th>Назначение</th><th>Решение</th></tr></thead>
<tbody>{rows}</tbody>
</table>"#,
            events.len()
        )
    };
    layout("События", &format!("<h1>События</h1>{body}"), true)
}

pub fn recordings_page(rows: &[RecordingRow]) -> String {
    let body = if rows.is_empty() {
        r#"<p class="lead">Записей сессий ещё нет.</p>
<p class="hint">SSH записывается через локальный прокси, пока агент запущен. На Windows окно mstsc снимается само.</p>"#
            .to_string()
    } else {
        let table = rows
            .iter()
            .map(|row| {
                format!(
                    r#"<tr>
<td>{}</td>
<td>{}</td>
<td>{}</td>
<td><code>{}:{}</code></td>
<td>{}</td>
<td><a href="/recordings/{}">смотреть</a></td>
</tr>"#,
                    esc(&format_unix(row.started_at)),
                    esc(&row.hostname),
                    protocol_label(&row.kind),
                    esc(&row.destination),
                    row.port,
                    esc(&row.username),
                    esc(&row.id)
                )
            })
            .collect::<String>();
        format!(
            r#"<p id="recording-count">Записей: {}</p>
<table>
<thead><tr><th>Начало</th><th>Агент</th><th>Протокол</th><th>Куда</th><th>Пользователь</th><th></th></tr></thead>
<tbody>{table}</tbody>
</table>"#,
            rows.len()
        )
    };
    layout(
        "Записи",
        &format!("<h1>Записи сессий</h1>{body}"),
        true,
    )
}

pub fn replay_page(row: &RecordingRow, frames: &[RecordingFrame], truncated: bool, solo: bool) -> String {
    let note = if truncated {
        r#"<p class="hint">Показана только первая часть записи.</p>"#
    } else {
        ""
    };
    let screen = if row.kind == "rdp" {
        video_markup(&row.id, frames)
    } else {
        player_markup(frames)
    };
    let ended = row
        .ended_at
        .map(|ts| format_unix(ts))
        .unwrap_or_else(|| "идёт".into());
    let intro = if solo {
        String::new()
    } else {
        format!(
            r#"<p><a href="/recordings">Все записи</a></p>
<h1>{}:{}</h1>
<p class="lead">{} · {} · {} · {} — {} · <code>{}</code></p>
{note}"#,
            esc(&row.destination),
            row.port,
            protocol_label(&row.kind),
            esc(&row.username),
            esc(&row.hostname),
            esc(&format_unix(row.started_at)),
            esc(&ended),
            esc(&row.agent_id)
        )
    };
    document(
        "Запись",
        &format!("{intro}{screen}"),
        true,
        if solo { "solo" } else { "" },
    )
}

#[derive(Serialize)]
struct PlayEvent<'a> {
    t: u64,
    s: &'a str,
}

fn video_markup(recording_id: &str, frames: &[RecordingFrame]) -> String {
    #[derive(Serialize)]
    struct VideoEvent {
        t: u64,
        n: u32,
    }
    let events: Vec<VideoEvent> = frames
        .iter()
        .filter(|frame| frame.direction == "frame")
        .filter_map(|frame| {
            Some(VideoEvent {
                t: frame.t_ms,
                n: frame.text.parse().ok()?,
            })
        })
        .collect();
    if events.is_empty() {
        return r#"<p id="session-screen">Кадров RDP пока нет.</p>"#.to_string();
    }
    let json = serde_json::to_string(&events)
        .unwrap_or_else(|_| "[]".into())
        .replace('<', "\\u003c");
    format!(
        r#"<div class="player" id="recording-player">
<div class="stage" id="play-stage"><img id="session-screen" class="screen video" data-id="{id}" alt="Кадр сессии RDP"></div>
<div class="controls">
<button type="button" id="play-toggle">Смотреть</button>
<input id="play-seek" type="range" min="0" max="1000" value="0" aria-label="Позиция видео">
<span id="play-time">00:00 / 00:00</span>
<label>Разрешение <select id="play-size" aria-label="Разрешение просмотра"><option value="fit" selected>По ширине</option><option value="800">800 px</option><option value="1024">1024 px</option><option value="1280">1280 px</option><option value="1600">1600 px</option><option value="1920">1920 px</option><option value="native">Исходное</option></select></label>
<label>Скорость <select id="play-speed"><option value="1" selected>1×</option><option value="2">2×</option><option value="4">4×</option><option value="8">8×</option></select></label>
<button type="button" id="play-pop">Отдельное окно</button>
<button type="button" id="play-full">На весь экран</button>
</div>
</div>
<script type="application/json" id="recording-frames">{json}</script>
<script>{VIDEO_JS}</script>"#,
        id = esc(recording_id)
    )
}

fn player_markup(frames: &[RecordingFrame]) -> String {
    let events: Vec<PlayEvent<'_>> = frames
        .iter()
        .filter(|frame| frame.direction != "in")
        .map(|frame| PlayEvent {
            t: frame.t_ms,
            s: frame.text.as_str(),
        })
        .collect();
    if events.is_empty() {
        return r#"<p id="session-screen">Вывода терминала пока нет.</p>"#.to_string();
    }
    let json = serde_json::to_string(&events)
        .unwrap_or_else(|_| "[]".into())
        .replace('<', "\\u003c");
    format!(
        r#"<div class="player" id="recording-player">
<pre id="session-screen" class="screen"></pre>
<div class="controls">
<button type="button" id="play-toggle">Смотреть</button>
<input id="play-seek" type="range" min="0" max="1000" value="0" aria-label="Позиция видео">
<span id="play-time">00:00 / 00:00</span>
<label>Скорость <select id="play-speed"><option value="1" selected>1×</option><option value="2">2×</option><option value="4">4×</option><option value="8">8×</option></select></label>
</div>
</div>
<script type="application/json" id="recording-frames">{json}</script>
<script>{PLAYER_JS}</script>"#
    )
}

pub fn replay_missing() -> String {
    layout(
        "Запись",
        r#"<h1>Запись не найдена</h1><p><a href="/recordings">Все записи</a></p>"#,
        true,
    )
}

const PLAYER_JS: &str = r####"
(function () {
  const host = document.getElementById("session-screen");
  const raw = document.getElementById("recording-frames");
  if (!host || !raw) return;
  const frames = JSON.parse(raw.textContent || "[]");
  frames.forEach((frame, index) => { frame.i = index; });
  frames.sort((a, b) => (a.t - b.t) || (a.i - b.i));
  const origin = frames.length ? (frames[0].t || 0) : 0;
  frames.forEach((frame) => { frame.t = Math.max(0, (frame.t || 0) - origin); });
  const cols = 120, rows = 24, total = cols * rows;
  let screen, alt, x, y, fg, bg, bold, saved, mode, csi, priv;
  const blank = () => ({ ch: " ", fg: "", bg: "", bold: false });
  function clearAll() { for (let i = 0; i < total; i++) screen[i] = blank(); }
  function clearRow(row) { for (let i = 0; i < cols; i++) screen[row * cols + i] = blank(); }
  function reset() {
    screen = new Array(total); alt = null; x = 0; y = 0; fg = ""; bg = ""; bold = false; saved = null;
    mode = 0; csi = ""; priv = false; clearAll();
  }
  function scroll() { screen.copyWithin(0, cols, total); clearRow(rows - 1); }
  function line() { y++; x = 0; if (y >= rows) { y = rows - 1; scroll(); } }
  function put(ch) {
    if (x >= cols) { x = 0; y++; if (y >= rows) { y = rows - 1; scroll(); } }
    screen[y * cols + x] = { ch: ch, fg: fg, bg: bg, bold: bold };
    x++;
  }
  function erase(start, end) { for (let i = start; i < end; i++) screen[i] = blank(); }
  function sgr(parts) {
    if (!parts.length) { fg = ""; bg = ""; bold = false; return; }
    parts.forEach((part) => {
      const n = part === "" ? 0 : Number(part);
      if (n === 0) { fg = ""; bg = ""; bold = false; }
      else if (n === 1) bold = true;
      else if (n === 22) bold = false;
      else if ((n >= 30 && n <= 37) || (n >= 90 && n <= 97)) fg = "c" + n;
      else if (n === 39) fg = "";
      else if ((n >= 40 && n <= 47) || (n >= 100 && n <= 107)) bg = "c" + n;
      else if (n === 49) bg = "";
    });
  }
  function num(parts, index, fallback) {
    const value = Number(parts[index]);
    return parts[index] !== undefined && parts[index] !== "" && Number.isFinite(value) ? value : fallback;
  }
  function csiDispatch(final) {
    const parts = csi.split(";");
    if (final === "A") y = Math.max(0, y - num(parts, 0, 1));
    else if (final === "B") y = Math.min(rows - 1, y + num(parts, 0, 1));
    else if (final === "C") x = Math.min(cols - 1, x + num(parts, 0, 1));
    else if (final === "D") x = Math.max(0, x - num(parts, 0, 1));
    else if (final === "G") x = Math.max(0, Math.min(cols - 1, num(parts, 0, 1) - 1));
    else if (final === "H" || final === "f") {
      y = Math.max(0, Math.min(rows - 1, num(parts, 0, 1) - 1));
      x = Math.max(0, Math.min(cols - 1, num(parts, 1, 1) - 1));
    } else if (final === "J") {
      const n = num(parts, 0, 0);
      if (n === 2 || n === 3) clearAll();
      else if (n === 1) erase(0, y * cols + x + 1);
      else erase(y * cols + x, total);
    } else if (final === "K") {
      const n = num(parts, 0, 0);
      if (n === 2) erase(y * cols, (y + 1) * cols);
      else if (n === 1) erase(y * cols, y * cols + x + 1);
      else erase(y * cols + x, (y + 1) * cols);
    } else if (final === "m") sgr(parts);
    else if ((final === "h" || final === "l") && priv) {
      const code = num(parts, 0, 0);
      if (code === 1049 || code === 47 || code === 1047) {
        if (final === "h" && !alt) { alt = screen; screen = new Array(total); clearAll(); }
        else if (final === "l" && alt) { screen = alt; alt = null; }
      }
    }
  }
  function step(cp) {
    const ch = String.fromCodePoint(cp);
    if (mode === 3) {
      if (cp === 7 || (cp === 92 && csi === "esc")) mode = 0;
      else csi = cp === 27 ? "esc" : "";
      return;
    }
    if (mode === 1) {
      if (ch === "[") { mode = 2; csi = ""; priv = false; return; }
      if (ch === "]") { mode = 3; csi = ""; return; }
      if (ch === "7") saved = { x: x, y: y, fg: fg, bg: bg, bold: bold };
      else if (ch === "8" && saved) { x = saved.x; y = saved.y; fg = saved.fg; bg = saved.bg; bold = saved.bold; }
      mode = 0;
      return;
    }
    if (mode === 2) {
      if (ch === "?") { priv = true; return; }
      if ((cp >= 48 && cp <= 57) || ch === ";") { csi += ch; return; }
      if (cp >= 64 && cp <= 126) { csiDispatch(ch); mode = 0; }
      return;
    }
    if (cp === 27) { mode = 1; return; }
    if (ch === "\n") { line(); return; }
    if (ch === "\r") { x = 0; return; }
    if (ch === "\b") { x = Math.max(0, x - 1); return; }
    if (ch === "\t") { x = Math.min(cols - 1, (Math.floor(x / 8) + 1) * 8); return; }
    if (cp < 32) return;
    put(ch);
  }
  function feed(text) {
    for (let i = 0; i < text.length; i++) {
      const cp = text.codePointAt(i);
      if (cp > 65535) i++;
      step(cp);
    }
  }
  const colors = {
    c30:"#3a3a3a", c31:"#e06c75", c32:"#98c379", c33:"#e5c07b", c34:"#61afef", c35:"#c678dd", c36:"#56b6c2", c37:"#dcdfe4",
    c90:"#767676", c91:"#ff7b86", c92:"#b5e890", c93:"#ffe08a", c94:"#8ec7ff", c95:"#e3a1f0", c96:"#7ee0ea", c97:"#ffffff",
    c40:"#3a3a3a", c41:"#5a2024", c42:"#1e3a24", c43:"#4a3b16", c44:"#16304a", c45:"#3a2044", c46:"#14383c", c47:"#444"
  };
  function render() {
    let html = "";
    for (let row = 0; row < rows; row++) {
      if (row) html += "\n";
      let col = 0;
      while (col < cols) {
        const cell = screen[row * cols + col];
        let next = col + 1;
        while (next < cols) {
          const other = screen[row * cols + next];
          if (other.fg !== cell.fg || other.bg !== cell.bg || other.bold !== cell.bold) break;
          next++;
        }
        let text = "";
        for (let i = col; i < next; i++) text += screen[row * cols + i].ch;
        let body = escapeHtml(text);
        if (row === y && col <= x && x < next) {
          const at = x - col;
          body = escapeHtml(text.slice(0, at)) + '<span class="cursor">' + escapeHtml(text.charAt(at) || " ") + "</span>" + escapeHtml(text.slice(at + 1));
        }
        let style = "";
        if (colors[cell.fg]) style += "color:" + colors[cell.fg] + ";";
        if (colors[cell.bg]) style += "background:" + colors[cell.bg] + ";";
        if (cell.bold) style += "font-weight:700;";
        html += style ? '<span style="' + style + '">' + body + "</span>" : body;
        col = next;
      }
    }
    host.innerHTML = html;
  }
  function escapeHtml(value) {
    return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  const duration = frames.reduce((max, frame) => Math.max(max, frame.t || 0), 0);
  let index = 0, clock = 0, playing = duration > 0, speed = 1, stamp = 0;
  const toggle = document.getElementById("play-toggle");
  const seek = document.getElementById("play-seek");
  const label = document.getElementById("play-time");
  const speedBox = document.getElementById("play-speed");
  function fmt(ms) {
    const sec = Math.max(0, Math.floor(ms / 1000));
    const min = Math.floor(sec / 60);
    const pad = (n) => String(n % 60).padStart(2, "0");
    return String(min).padStart(2, "0") + ":" + pad(sec);
  }
  function chrome() {
    if (label) label.textContent = fmt(clock) + " / " + fmt(duration);
    if (seek && document.activeElement !== seek) seek.value = duration ? String(Math.round(clock / duration * 1000)) : "0";
    if (toggle) toggle.textContent = playing ? "Пауза" : "Смотреть";
  }
  function seekTo(ms) {
    ms = Math.max(0, Math.min(duration, ms));
    if (ms < clock) { reset(); index = 0; }
    clock = ms;
    while (index < frames.length && (frames[index].t || 0) <= clock) {
      feed(frames[index].s || "");
      index++;
    }
    render();
    chrome();
  }
  reset();
  seekTo(0);
  if (toggle) toggle.addEventListener("click", () => {
    if (!playing && clock >= duration && duration > 0) seekTo(0);
    playing = !playing;
    chrome();
  });
  if (seek) seek.addEventListener("input", () => seekTo(duration * Number(seek.value) / 1000));
  if (speedBox) speedBox.addEventListener("change", () => { speed = Number(speedBox.value) || 1; });
  function tick(now) {
    if (!stamp) stamp = now;
    if (playing) {
      const next = clock + Math.min(100, now - stamp) * speed;
      if (next >= duration) { seekTo(duration); playing = false; chrome(); }
      else seekTo(next);
    }
    stamp = now;
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
})();
"####;

const VIDEO_JS: &str = r####"
(function () {
  const host = document.getElementById("session-screen");
  const raw = document.getElementById("recording-frames");
  if (!host || !raw) return;
  const frames = JSON.parse(raw.textContent || "[]");
  frames.forEach((frame, index) => { frame.i = index; });
  frames.sort((a, b) => (a.t - b.t) || (a.i - b.i));
  const origin = frames.length ? (frames[0].t || 0) : 0;
  frames.forEach((frame) => { frame.t = Math.max(0, (frame.t || 0) - origin); });
  const duration = frames.reduce((max, frame) => Math.max(max, frame.t || 0), 0);
  let clock = 0, playing = duration > 0, speed = 1, stamp = 0, shown = -1;
  const toggle = document.getElementById("play-toggle");
  const seek = document.getElementById("play-seek");
  const label = document.getElementById("play-time");
  const speedBox = document.getElementById("play-speed");
  const sizeBox = document.getElementById("play-size");
  const recordingId = host.getAttribute("data-id") || "";
  const sizeKey = "keeppam-rdp-view";
  function fmt(ms) {
    const sec = Math.max(0, Math.floor(ms / 1000));
    const min = Math.floor(sec / 60);
    const pad = (n) => String(n % 60).padStart(2, "0");
    return String(min).padStart(2, "0") + ":" + pad(sec);
  }
  function chrome() {
    if (label) label.textContent = fmt(clock) + " / " + fmt(duration);
    if (seek && document.activeElement !== seek) seek.value = duration ? String(Math.round(clock / duration * 1000)) : "0";
    if (toggle) toggle.textContent = playing ? "Пауза" : "Смотреть";
  }
  function show(ms) {
    clock = Math.max(0, Math.min(duration, ms));
    let chosen = 0;
    for (let i = 0; i < frames.length; i++) {
      if ((frames[i].t || 0) <= clock) chosen = i;
      else break;
    }
    const frame = frames[chosen];
    if (frame && shown !== frame.n) {
      shown = frame.n;
      host.src = "/recordings/" + encodeURIComponent(recordingId) + "/frame/" + frame.n;
    }
    chrome();
  }
  show(0);
  if (toggle) toggle.addEventListener("click", () => {
    if (!playing && clock >= duration && duration > 0) show(0);
    playing = !playing;
    chrome();
  });
  const player = document.getElementById("recording-player");
  const pop = document.getElementById("play-pop");
  const full = document.getElementById("play-full");
  function fullscreenOn() {
    return document.fullscreenElement === player || document.webkitFullscreenElement === player;
  }
  function applySize() {
    const fitted = fullscreenOn() || (document.body.classList.contains("solo") && (!sizeBox || sizeBox.value === "fit"));
    if (fitted) {
      host.style.width = "auto";
      host.style.height = "auto";
      host.style.maxWidth = "100%";
      host.style.maxHeight = fullscreenOn() ? "calc(100vh - 64px)" : "calc(100vh - 58px)";
      if (full) full.textContent = fullscreenOn() ? "Свернуть" : "На весь экран";
      return;
    }
    if (full) full.textContent = "На весь экран";
    const value = sizeBox ? sizeBox.value : "fit";
    if (value === "native") {
      host.style.width = host.naturalWidth ? host.naturalWidth + "px" : "auto";
      host.style.maxWidth = "none";
      host.style.maxHeight = "none";
      return;
    }
    const width = Number(value);
    if (!width) {
      host.style.width = "100%";
      host.style.maxWidth = "100%";
      host.style.maxHeight = "720px";
      return;
    }
    host.style.width = width + "px";
    host.style.maxWidth = "none";
    host.style.maxHeight = "none";
  }
  function labelSizes() {
    if (!sizeBox || !host.naturalWidth || !host.naturalHeight) return;
    for (const option of sizeBox.options) {
      const width = Number(option.value);
      if (!width) continue;
      const height = Math.max(1, Math.round(host.naturalHeight * width / host.naturalWidth));
      option.textContent = width + "×" + height;
    }
  }
  if (sizeBox) {
    try {
      const saved = localStorage.getItem(sizeKey);
      if (saved && Array.from(sizeBox.options).some((option) => option.value === saved)) sizeBox.value = saved;
    } catch (err) {}
    sizeBox.addEventListener("change", () => {
      try { localStorage.setItem(sizeKey, sizeBox.value); } catch (err) {}
      applySize();
    });
  }
  host.addEventListener("load", () => { labelSizes(); applySize(); });
  if (pop) pop.addEventListener("click", () => {
    const opened = window.open(location.pathname + "?solo=1", "keeppam-rdp-" + recordingId, "popup=yes,width=1280,height=800,resizable=yes,scrollbars=yes");
    if (opened) opened.focus();
  });
  if (full && player) full.addEventListener("click", () => {
    if (fullscreenOn()) {
      const exit = document.exitFullscreen || document.webkitExitFullscreen;
      if (exit) exit.call(document);
      return;
    }
    const enter = player.requestFullscreen || player.webkitRequestFullscreen;
    if (enter) enter.call(player);
  });
  document.addEventListener("fullscreenchange", applySize);
  document.addEventListener("webkitfullscreenchange", applySize);
  applySize();
  if (seek) seek.addEventListener("input", () => show(duration * Number(seek.value) / 1000));
  if (speedBox) speedBox.addEventListener("change", () => { speed = Number(speedBox.value) || 1; });
  function tick(now) {
    if (!stamp) stamp = now;
    if (playing) {
      const next = clock + Math.min(100, now - stamp) * speed;
      if (next >= duration) { show(duration); playing = false; chrome(); }
      else show(next);
    }
    stamp = now;
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
})();
"####;

fn protocol_label(kind: &str) -> &'static str {
    if kind == "rdp" { "RDP" } else { "SSH" }
}

fn decision_code(decision: Option<&Decision>) -> &'static str {
    match decision {
        Some(Decision::Allow) => "allow",
        Some(Decision::WouldDeny) => "would_deny",
        Some(Decision::Ignore) => "ignore",
        None => "",
    }
}

fn decision_label(decision: Option<&Decision>) -> String {
    match decision {
        Some(Decision::Allow) => "пропустить".into(),
        Some(Decision::WouldDeny) => "был бы запрет".into(),
        Some(Decision::Ignore) => "вне политики".into(),
        None => "—".into(),
    }
}

pub struct AgentPackage {
    pub id: &'static str,
    pub system: &'static str,
    pub filename: &'static str,
    pub size: Option<u64>,
}

pub fn agent_packages(dir: &std::path::Path) -> Vec<AgentPackage> {
    const FILES: &[(&str, &str, &str)] = &[
        ("windows", "Windows", "endpoint-agent-windows-x86_64.exe"),
        ("linux", "Linux", "endpoint-agent-linux-x86_64"),
        ("macos", "macOS (Apple Silicon)", "endpoint-agent-macos-aarch64"),
    ];
    FILES
        .iter()
        .map(|(id, system, filename)| AgentPackage {
            id,
            system,
            filename,
            size: std::fs::metadata(dir.join(filename)).ok().map(|meta| meta.len()),
        })
        .collect()
}

pub fn downloads_page(packages: &[AgentPackage]) -> String {
    let cards = packages
        .iter()
        .map(|package| {
            let file = match package.size {
                Some(size) => format!(
                    r#"<p><a class="button" href="/downloads/{}">Скачать {}</a></p>
<p class="hint">{} · {}</p>"#,
                    esc(package.id),
                    esc(package.filename),
                    esc(package.filename),
                    esc(&format_size(size))
                ),
                None => format!(
                    r#"<p class="hint">Файл {} ещё не выложен.</p>"#,
                    esc(package.filename)
                ),
            };
            format!(
                r#"<article class="card"><h2>{}</h2>{file}</article>"#,
                esc(package.system)
            )
        })
        .collect::<String>();
    layout(
        "Скачать",
        &format!(
            r#"<h1>Скачать агент</h1>
<p class="lead">Программа ставится на рабочую станцию и записывает сессии, которые пользователь открывает с этого компьютера.</p>
<p class="hint">Токен зачисления выпускается на странице <a href="/agents">Агенты</a>. Порядок установки — в <a href="/help">Помощи</a>.</p>
<div class="cards">{cards}</div>"#
        ),
        true,
    )
}

pub fn help_page(base: &str) -> String {
    let base = esc(base);
    layout(
        "Помощь",
        &format!(
            r#"<h1>Установка агента</h1>
<p class="lead">Агент работает на компьютере пользователя. Адрес сервиса для этой страницы: <code>{base}</code>.</p>
<p>Сначала на странице <a href="/agents">Агенты</a> выпустите токен. Он показывается один раз. Файл программы берите на странице <a href="/downloads">Скачать</a>.</p>
<h2>Windows</h2>
<ol>
<li>Скачайте <code>endpoint-agent-windows-x86_64.exe</code> и положите его, например, в <code>D:\PAM\endpoint-agent.exe</code>.</li>
<li>Запустите файл. В трее появится значок KeepPAM.</li>
<li>Щёлкните значок, откройте конфигурацию и укажите IP сервиса, порт и токен. Сохраните.</li>
<li>Пока агент в трее, SSH, PuTTY и окно mstsc записываются. Записи открываются в пункте «Записи».</li>
<li>Остановка — пункт «Остановить агент» в меню значка. После остановки перехват SSH снимается.</li>
</ol>
<h2>Linux</h2>
<ol>
<li>Скачайте <code>endpoint-agent-linux-x86_64</code>, сделайте его исполняемым и запустите с токеном.</li>
</ol>
<pre class="cmd">chmod +x endpoint-agent-linux-x86_64
./endpoint-agent-linux-x86_64 --server {base} --enroll-token ТОКЕН</pre>
<ol start="2">
<li>Пока процесс запущен, <code>ssh</code> этой учётной записи идёт через локальный прокси. Каталог состояния — <code>agent-state</code> рядом с файлом, а если туда нельзя писать, то <code>~/.local/share/keeppam-agent</code>.</li>
<li>Остановка снимает перехват из <code>~/.ssh/config</code>.</li>
</ol>
<pre class="cmd">./endpoint-agent-linux-x86_64 stop</pre>
<h2>macOS</h2>
<ol>
<li>Файл рассчитан на Mac с процессором Apple (M1 и новее). Скачайте <code>endpoint-agent-macos-aarch64</code>, сделайте его исполняемым и запустите с токеном.</li>
</ol>
<pre class="cmd">chmod +x endpoint-agent-macos-aarch64
./endpoint-agent-macos-aarch64 --server {base} --enroll-token ТОКЕН</pre>
<ol start="2">
<li>Пока процесс запущен, <code>ssh</code> этой учётной записи идёт через локальный прокси. Каталог состояния — <code>agent-state</code> рядом с файлом, а если туда нельзя писать, то <code>~/Library/Application Support/KeepPAM/agent</code>.</li>
<li>Остановка снимает перехват из <code>~/.ssh/config</code>.</li>
</ol>
<pre class="cmd">./endpoint-agent-macos-aarch64 stop</pre>
<p class="hint">Агент запускайте под той же учётной записью, которой пользуются для ssh: правится её файл <code>~/.ssh/config</code>.</p>"#
        ),
        true,
    )
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} МБ", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.0} КБ", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} Б")
    }
}

fn short_id(value: &str) -> String {
    value.chars().take(8).collect()
}

fn layout(title: &str, body: &str, logged_in: bool) -> String {
    document(title, body, logged_in, "")
}

fn document(title: &str, body: &str, logged_in: bool, body_class: &str) -> String {
    let nav = if logged_in {
        r#"<nav>
<a href="/agents">Агенты</a>
<a href="/downloads">Скачать</a>
<a href="/help">Помощь</a>
<a href="/policy">Политика</a>
<a href="/events">События</a>
<a href="/recordings">Записи</a>
<form method="post" action="/logout"><button type="submit">Выход</button></form>
</nav>"#
    } else {
        ""
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Endpoint Agent</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ margin: 0; font: 16px/1.45 system-ui, sans-serif; }}
header {{ display: flex; justify-content: space-between; gap: 16px; align-items: center; padding: 16px 24px; border-bottom: 1px solid #ccc; }}
header span {{ display: block; font-size: 13px; opacity: 0.7; }}
nav {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }}
h2 {{ font-size: 18px; margin: 28px 0 8px; }}
ol {{ margin: 8px 0 16px; padding-left: 1.3em; }}
pre.cmd {{ margin: 8px 0 16px; padding: 12px; overflow: auto; border: 1px solid #ccc; }}
.cards {{ display: grid; gap: 12px; margin-top: 16px; }}
.card {{ border: 1px solid #ccc; padding: 16px; }}
.card h2 {{ margin-top: 0; }}
a.button {{ display: inline-block; margin-top: 8px; padding: 8px 14px; border: 1px solid #888; text-decoration: none; color: inherit; }}
nav a {{ color: inherit; }}
main {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
h1 {{ margin: 0 0 8px; font-size: 24px; }}
.lead, .hint {{ opacity: 0.75; }}
form {{ display: grid; gap: 12px; margin: 16px 0 24px; }}
label {{ display: grid; gap: 6px; font-weight: 600; }}
input, textarea, button {{ font: inherit; }}
input, textarea {{ width: 100%; box-sizing: border-box; padding: 8px; }}
button {{ width: fit-content; padding: 8px 14px; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ccc; vertical-align: top; }}
code {{ font-family: ui-monospace, monospace; word-break: break-all; }}
.player {{ background: #0c0c0c; border-radius: 10px; overflow: hidden; margin-top: 16px; }}
.stage {{ background: #0c0c0c; overflow: auto; max-height: calc(100vh - 240px); }}
.screen {{ background: #0c0c0c; color: #e8e8e8; margin: 0; padding: 12px 14px; height: 420px; overflow-x: auto; overflow-y: hidden; white-space: pre; font: 13px/1.25 ui-monospace, monospace; }}
img.screen {{ display: block; width: 100%; max-width: 100%; height: auto; max-height: 720px; margin: 0 auto; object-fit: contain; padding: 0; white-space: normal; }}
.cursor {{ background: #e8e8e8; color: #111; }}
.controls {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: center; padding: 10px 12px; background: #161616; color: #eee; }}
.controls button, .controls select {{ width: auto; }}
.controls input[type="range"] {{ width: auto; flex: 1; padding: 0; }}
.controls label {{ font-weight: 500; display: flex; gap: 8px; align-items: center; }}
.player:fullscreen, .player:-webkit-full-screen {{ width: 100%; height: 100%; border-radius: 0; display: flex; flex-direction: column; background: #000; }}
.player:fullscreen .stage, .player:-webkit-full-screen .stage {{ flex: 1; max-height: none; display: flex; align-items: center; justify-content: center; }}
body.solo {{ background: #0c0c0c; }}
body.solo header {{ display: none; }}
body.solo main {{ max-width: none; height: 100vh; padding: 0; box-sizing: border-box; }}
body.solo .player {{ margin: 0; min-height: 100vh; border-radius: 0; display: flex; flex-direction: column; }}
body.solo .stage {{ flex: 1; max-height: none; display: flex; align-items: center; justify-content: center; }}
.error {{ color: #9b1c1c; }}
.notice {{ padding: 12px; border: 1px solid #ccc; margin: 12px 0; }}
</style>
</head>
<body class="{body_class}">
<header>
<div><strong>KeepPAM Endpoint Agent</strong><span>отдельный сервис, не консоль KeepPAM</span></div>
{nav}
</header>
<main>
{body}
</main>
</body>
</html>"#
    )
}

pub fn esc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_ports(value: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let port = part
            .parse::<u16>()
            .map_err(|_| format!("некорректный порт {part}"))?;
        if port == 0 {
            return Err("порт 0 не используется".into());
        }
        ports.push(port);
    }
    if ports.is_empty() {
        return Err("не указаны порты".into());
    }
    Ok(ports)
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn format_unix(ts: i64) -> String {
    if ts <= 0 {
        return "нет".into();
    }
    let days = ts.div_euclid(86_400);
    let sod = ts.rem_euclid(86_400) as u32;
    let hour = sod / 3600;
    let minute = (sod % 3600) / 60;
    let second = sod % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_page_is_a_timed_player() {
        let row = RecordingRow {
            id: "rec".into(),
            agent_id: "agent".into(),
            hostname: "desk".into(),
            destination: "10.0.0.8".into(),
            port: 22,
            username: "alice".into(),
            started_at: 1,
            ended_at: Some(2),
            kind: "ssh".into(),
        };
        let frames = vec![
            RecordingFrame {
                t_ms: 0,
                direction: "out".into(),
                text: "hello-session\n".into(),
            },
            RecordingFrame {
                t_ms: 800,
                direction: "out".into(),
                text: "second line\n".into(),
            },
        ];
        let page = replay_page(&row, &frames, false, false);
        assert!(page.contains("id=\"recording-player\""));
        assert!(page.contains("id=\"session-screen\""));
        assert!(page.contains("id=\"play-seek\""));
        assert!(page.contains("hello-session"));
        assert!(!page.contains("id=\"play-size\""));
        assert!(!page.contains("id=\"play-full\""));
        assert!(!page.contains("<pre id=\"session-screen\" class=\"screen\">hello-session"));
    }

    #[test]
    fn replay_page_plays_rdp_frames_as_images() {
        let row = RecordingRow {
            id: "11111111-1111-1111-1111-111111111111".into(),
            agent_id: "agent".into(),
            hostname: "desk".into(),
            destination: "10.1.1.8".into(),
            port: 3389,
            username: "rdp".into(),
            started_at: 1,
            ended_at: Some(2),
            kind: "rdp".into(),
        };
        let frames = vec![
            RecordingFrame {
                t_ms: 0,
                direction: "frame".into(),
                text: "0".into(),
            },
            RecordingFrame {
                t_ms: 1000,
                direction: "frame".into(),
                text: "1".into(),
            },
        ];
        let page = replay_page(&row, &frames, false, false);
        assert!(page.contains("class=\"screen video\""));
        assert!(page.contains("id=\"play-size\""));
        assert!(page.contains("id=\"play-pop\""));
        assert!(page.contains("id=\"play-full\""));
        assert!(page.contains("Отдельное окно"));
        assert!(page.contains("На весь экран"));
        assert!(page.contains("По ширине"));
        assert!(page.contains("Исходное"));
        let solo = replay_page(&row, &frames, false, true);
        assert!(solo.contains("<body class=\"solo\">"));
        assert!(solo.contains("id=\"play-full\""));
        assert!(!solo.contains("Все записи"));
        assert!(page.contains("data-id=\"11111111-1111-1111-1111-111111111111\""));
        assert!(page.contains("/frame/"));
        assert!(page.contains(">RDP<") || page.contains("RDP"));
        assert!(!page.contains("<pre id=\"session-screen\""));
    }

    #[test]
    fn download_page_links_only_ready_files_and_help_explains_install() {
        let dir = std::env::temp_dir().join(format!("agentd-downloads-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("endpoint-agent-linux-x86_64"), b"linux-agent").unwrap();
        let packages = agent_packages(&dir);
        let page = downloads_page(&packages);
        assert!(page.contains("href=\"/downloads/linux\""));
        assert!(page.contains("href=\"/help\""));
        assert!(!page.contains("href=\"/downloads/windows\""));
        assert!(page.contains("endpoint-agent-macos-aarch64"));
        let help = help_page("http://10.0.126.235:8090");
        assert!(help.contains("Остановить агент"));
        assert!(help.contains("endpoint-agent-linux-x86_64 stop"));
        assert!(help.contains("endpoint-agent-macos-aarch64 stop"));
        assert!(help.contains("mstsc"));
        assert!(help.contains("http://10.0.126.235:8090"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
