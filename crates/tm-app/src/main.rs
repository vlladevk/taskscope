//! Диспетчер — приложение в трее. Держит движок (сбор раз в секунду, история за сутки),
//! канал `\\.\pipe\tm` для CLI и агентов и окно на WebView2.
//!
//! Один экземпляр на машину: повторный запуск показывает окно уже работающего,
//! а запущенный отдельно `tm daemon` уступает место приложению (история сохраняется).
//!
//! Ключи запуска: `--tray` — стартовать свёрнутым в трей (так делает автозапуск),
//! `--replace` — сменить работающий экземпляр (перезапуск от администратора).
#![windows_subsystem = "windows"]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::image::Image;
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent};
use tm_core::engine::{default_store, Engine};
use tm_core::{pipe, service, system, Service};

const AUTOSTART_NAME: &str = "Диспетчер задач (tm)";

/// Предупреждения и ошибки Tauri/wry — в журнал движка: иначе, например, сбой создания окна
/// из другого потока пропадает бесследно.
struct EngineLog;
static ENGINE: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
impl log::Log for EngineLog {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Warn
    }
    fn log(&self, r: &log::Record) {
        if let (true, Some(e)) = (self.enabled(r.metadata()), ENGINE.get()) {
            let lvl = if r.level() == log::Level::Error { "red" } else { "yel" };
            e.log(lvl, format!("[{}] {}", r.target(), r.args()), None);
        }
    }
    fn flush(&self) {}
}
/// Скрытое окно дольше этого времени закрывается целиком: WebView2 отдаёт свою память (~100 МБ).
/// Движок и трей продолжают работать, следующее открытие займёт на полсекунды дольше.
const SAVE_MEMORY_AFTER: Duration = Duration::from_secs(10 * 60);

struct Ui {
    service: Arc<Service>,
    hidden_since: Mutex<Option<Instant>>,
    /// окно создано скрытым, а должно быть развёрнутым
    maximize_on_show: AtomicBool,
    /// WebView2 переведён в режим экономии памяти
    saving_memory: AtomicBool,
}

/* ------------------------------------------------------------------ окно */

#[derive(Serialize, Deserialize, Clone, Copy)]
struct Geometry {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    max: bool,
}

fn geometry_file() -> Option<PathBuf> {
    default_store().map(|p| p.with_file_name("window.json"))
}

fn load_geometry() -> Option<Geometry> {
    serde_json::from_slice(&std::fs::read(geometry_file()?).ok()?).ok()
}

fn save_geometry(w: &WebviewWindow) {
    let (Ok(pos), Ok(size), Ok(scale)) = (w.outer_position(), w.inner_size(), w.scale_factor()) else { return };
    let max = w.is_maximized().unwrap_or(false);
    // у свёрнутого окна координаты бессмысленные (−32000) — не сохраняем
    if w.is_minimized().unwrap_or(false) || pos.x <= -30000 {
        return;
    }
    let g = Geometry { x: pos.x as f64 / scale, y: pos.y as f64 / scale, w: size.width as f64 / scale, h: size.height as f64 / scale, max };
    if let (Some(path), Ok(bytes)) = (geometry_file(), serde_json::to_vec(&g)) {
        let _ = std::fs::write(path, bytes);
    }
}

/// Лежит ли точка на каком-нибудь из подключённых мониторов (монитор могли отключить).
fn on_screen(app: &AppHandle, g: &Geometry) -> bool {
    app.available_monitors().unwrap_or_default().iter().any(|m| {
        let s = m.scale_factor();
        let (x, y) = (m.position().x as f64 / s, m.position().y as f64 / s);
        let (w, h) = (m.size().width as f64 / s, m.size().height as f64 / s);
        g.x + 80.0 >= x && g.x + 80.0 < x + w && g.y + 10.0 >= y && g.y + 10.0 < y + h
    })
}

/// Главное окно создаётся один раз при запуске (в режиме трея — скрытым) и дальше только
/// показывается и прячется. Создавать WebView2 в уже работающем приложении ненадёжно: иногда оно
/// падает с ERROR_NOT_ENOUGH_QUOTA (0x80070718), а Tauri лишь пишет это в свой журнал и оставляет
/// в списке мёртвое окно, которое не отвечает на запросы, — его не считаем.
fn main_window(app: &AppHandle) -> Option<WebviewWindow> {
    app.get_webview_window("main").filter(|w| w.is_visible().is_ok())
}

fn build_main(app: &AppHandle, visible: bool) -> tauri::Result<WebviewWindow> {
    let g = load_geometry();
    let mut b = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Диспетчер задач")
        .inner_size(g.map_or(1360.0, |g| g.w.max(900.0)), g.map_or(860.0, |g| g.h.max(560.0)))
        .min_inner_size(900.0, 560.0)
        .theme(Some(tauri::Theme::Dark))
        .background_color(tauri::window::Color(32, 32, 32, 255))
        .visible(visible);
    match g {
        // развернуть скрытое окно нельзя — Windows при этом его покажет; развернём при первом показе
        Some(g) if on_screen(app, &g) => {
            b = b.position(g.x, g.y).maximized(g.max && visible);
            app.state::<Ui>().maximize_on_show.store(g.max && !visible, Ordering::Relaxed);
        }
        _ => b = b.center(),
    }
    let w = b.build()?;
    if visible {
        let _ = w.set_focus();
    }
    Ok(w)
}

/// WebView2 не считает страницу скрытой, когда окно спрятано в трей или свёрнуто, —
/// сообщаем сами: скрытая страница не опрашивает движок и ничего не рисует.
fn set_page_hidden(w: &WebviewWindow, hidden: bool) {
    let _ = w.eval(format!("window.__tmHidden={hidden}"));
}

/// Долго скрытое окно: просим WebView2 отдать память, как браузер со свёрнутой вкладкой;
/// при показе возвращаем обычный режим.
fn memory_saver(w: &WebviewWindow, save: bool) {
    let _ = w.with_webview(move |pw| unsafe {
        use webview2_com::Microsoft::Web::WebView2::Win32::*;
        use windows::core::Interface;
        let c = pw.controller();
        let _ = c.SetIsVisible(!save);
        if let Ok(core) = c.CoreWebView2().and_then(|v| v.cast::<ICoreWebView2_19>()) {
            let level = if save { COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW } else { COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL };
            let _ = core.SetMemoryUsageTargetLevel(level);
        }
    });
}

fn show_main(app: &AppHandle) {
    let ui = app.state::<Ui>();
    *ui.hidden_since.lock().unwrap() = None;
    let Some(w) = main_window(app) else { return relaunch_with_window(app) };
    let _ = w.unminimize();
    let _ = w.show();
    if ui.maximize_on_show.swap(false, Ordering::Relaxed) {
        let _ = w.maximize();
    }
    if ui.saving_memory.swap(false, Ordering::Relaxed) {
        memory_saver(&w, false);
    }
    set_page_hidden(&w, false);
    let _ = w.set_focus();
}

/// Окна нет — WebView2 упал или не создался. Перезапускаемся с окном: при старте оно создаётся
/// надёжно. Новый экземпляр сам попросит этот завершиться (--replace), история сохранится.
fn relaunch_with_window(app: &AppHandle) {
    let engine = &app.state::<Ui>().service.engine;
    engine.log("yel", "Окно диспетчера пропало — перезапускаю приложение".into(), None);
    if let Err(e) = std::env::current_exe().and_then(|exe| system::spawn_detached(&exe, &["--replace"])) {
        engine.log("red", format!("Не удалось перезапустить приложение: {e}"), None);
    }
}

fn hide_main(app: &AppHandle) {
    if let Some(w) = main_window(app) {
        save_geometry(&w);
        let _ = w.hide();
        set_page_hidden(&w, true);
        *app.state::<Ui>().hidden_since.lock().unwrap() = Some(Instant::now());
    }
}

fn toggle_main(app: &AppHandle) {
    let shown = main_window(app).is_some_and(|w| w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false));
    if shown {
        hide_main(app)
    } else {
        show_main(app)
    }
}

/* ------------------------------------------------------------------ трей */

/// Значок трея — мини-график загрузки ЦП за последние 15 секунд (как в Process Explorer).
fn tray_icon(cpu: &[f32]) -> Image<'static> {
    const N: usize = 32;
    let mut px = vec![0u8; N * N * 4];
    let mut put = |x: usize, y: usize, c: [u8; 4]| {
        let o = (y * N + x) * 4;
        px[o..o + 4].copy_from_slice(&c);
    };
    let last = cpu.last().copied().unwrap_or(0.0);
    let col: [u8; 3] = if last >= 90.0 {
        [255, 110, 110]
    } else if last >= 60.0 {
        [252, 205, 60]
    } else {
        [76, 194, 255]
    };
    for y in 0..N {
        for x in 0..N {
            let edge = x == 0 || y == 0 || x == N - 1 || y == N - 1;
            put(x, y, if edge { [200, 200, 200, 255] } else { [16, 16, 16, 235] });
        }
    }
    // 15 столбиков по 2 пикселя внутри рамки
    let inner = N - 2;
    for (i, v) in cpu.iter().rev().take(inner / 2).enumerate() {
        let h = ((v.clamp(0.0, 100.0) / 100.0) * inner as f32).round() as usize;
        for k in 0..2 {
            let x = N - 2 - (i * 2 + k);
            for dy in 0..h {
                let y = N - 2 - dy;
                let top = dy + 1 == h;
                put(x, y, if top { [col[0], col[1], col[2], 255] } else { [col[0] / 10 * 7, col[1] / 10 * 7, col[2] / 10 * 7, 255] });
            }
        }
    }
    Image::new_owned(px, N as u32, N as u32)
}

fn tray_loop(app: AppHandle, engine: Engine) {
    let mut seq = 0;
    let mut cpu: Vec<f32> = vec![0.0; 15];
    loop {
        let Some(s) = engine.wait_newer(seq, Duration::from_secs(3)) else { continue };
        if s.seq == seq {
            continue;
        }
        seq = s.seq;
        cpu.remove(0);
        cpu.push(s.frame.system.cpu);
        let m = &s.frame.system.memory;
        let red = s.issues.iter().filter(|i| i.level == "red").count();
        let mut tip = format!("Диспетчер задач\nЦП {:.0} % · память {} %", s.frame.system.cpu, m.load_pct);
        if let Some(top) = s.apps.iter().max_by(|a, b| a.cpu.total_cmp(&b.cpu)).filter(|a| a.cpu >= 5.0) {
            tip.push_str(&format!("\nбольше всех: {} — {:.0} %", top.title.chars().take(40).collect::<String>(), top.cpu));
        }
        if red > 0 {
            tip.push_str(&format!("\nпроблем: {red}"));
        }
        if let Some(t) = app.tray_by_id("main") {
            let _ = t.set_icon(Some(tray_icon(&cpu)));
            let _ = t.set_tooltip(Some(tip));
        }
        // долго скрытое окно: WebView2 отдаёт память (само окно живёт — см. main_window)
        let ui = app.state::<Ui>();
        let stale = ui.hidden_since.lock().unwrap().is_some_and(|t| t.elapsed() >= SAVE_MEMORY_AFTER);
        if stale {
            *ui.hidden_since.lock().unwrap() = None;
            if let Some(w) = main_window(&app) {
                ui.saving_memory.store(true, Ordering::Relaxed);
                memory_saver(&w, true);
            }
        }
    }
}

/* ------------------------------------------------------------------ команды окна */

/// Любой метод движка. Окно работает с правами приложения — действия разрешены.
#[tauri::command]
async fn rpc(ui: tauri::State<'_, Ui>, method: String, params: Option<Value>) -> Result<Value, String> {
    let service = ui.service.clone();
    let params = params.unwrap_or(Value::Null);
    tauri::async_runtime::spawn_blocking(move || service.call(&method, &params)).await.map_err(|e| e.to_string())?
}

fn autostart_cmd() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    Some(format!("\"{}\" --tray", exe.display()))
}

#[tauri::command]
async fn app_cmd(app: AppHandle, cmd: String, arg: Option<Value>) -> Result<Value, String> {
    match cmd.as_str() {
        "hide" => hide_main(&app),
        "quit" => app.exit(0),
        "admin" => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            // новый экземпляр сам попросит этот завершиться (--replace); отказ в UAC — просто ошибка
            system::shell_execute("runas", &exe.display().to_string(), "--replace").map_err(|_| "запуск от администратора отменён".to_string())?;
        }
        "autostart_get" => return Ok(json!(system::autostart_get(AUTOSTART_NAME).is_some())),
        "autostart_set" => {
            let on = arg.as_ref().and_then(Value::as_bool).unwrap_or(false);
            let c = autostart_cmd();
            system::autostart_set(AUTOSTART_NAME, if on { c.as_deref() } else { None }).map_err(|e| e.to_string())?;
            return Ok(json!(system::autostart_get(AUTOSTART_NAME).is_some()));
        }
        _ => return Err(format!("неизвестная команда «{cmd}»")),
    }
    Ok(Value::Null)
}

/* ------------------------------------------------------------------ один экземпляр */

fn wait_pipe_gone() {
    let until = Instant::now() + Duration::from_secs(6);
    while Instant::now() < until {
        match pipe::call("ping", Value::Null, Duration::from_millis(500)) {
            Err(e) if pipe::is_not_running(&e) => return,
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// true — продолжать запуск; false — уже работает другой экземпляр, мы ему всё передали.
fn claim_instance(tray: bool, replace: bool) -> bool {
    let hello = if tray || replace { "app_hello" } else { "app_show" };
    match pipe::call(hello, Value::Null, Duration::from_secs(3)) {
        Ok(_) if !replace => false,
        Ok(_) => {
            let _ = pipe::call("app_quit", Value::Null, Duration::from_secs(2));
            wait_pipe_gone();
            true
        }
        Err(e) if pipe::is_not_running(&e) => true,
        // отвечает, но про окно не знает — это `tm daemon`: просим уступить (он сохранит историю)
        Err(e) if e.to_string().contains("неизвестный метод") => {
            let _ = pipe::call("shutdown", Value::Null, Duration::from_secs(2));
            wait_pipe_gone();
            true
        }
        Err(_) => true,
    }
}

fn start_pipe(app: AppHandle, service: Arc<Service>) {
    let handler: pipe::Handler = Arc::new(move |m: &str, p: &Value| match m {
        "app_hello" => Ok(json!(true)),
        "app_show" => {
            show_main(&app);
            Ok(json!(true))
        }
        // ВРЕМЕННО, диагностика: уничтожить / заново создать окно
        "app_debug_window" => {
            let a = app.clone();
            let what = p.as_str().unwrap_or("").to_string();
            let (tx, rx) = std::sync::mpsc::channel();
            let _ = app.run_on_main_thread(move || {
                let r = match what.as_str() {
                    "destroy" => main_window(&a).map(|w| w.destroy().map_err(|e| e.to_string())).unwrap_or(Ok(())),
                    "create" => build_main(&a, true).map(|_| ()).map_err(|e| e.to_string()),
                    _ => Err("destroy|create".into()),
                };
                let _ = tx.send(r);
            });
            let r = rx.recv_timeout(Duration::from_secs(20)).map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_millis(1500));
            Ok(json!({ "result": r.err(), "alive": main_window(&app).is_some() }))
        }
        "app_quit" | "shutdown" => {
            let a = app.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                a.exit(0);
            });
            Ok(json!(true))
        }
        m if service::is_mutating(m) => Err("действия через канал не выполняются: клиент выполняет их сам, со своими правами".into()),
        m => service.call(m, p),
    });
    std::thread::Builder::new()
        .name("tm-pipe-server".into())
        .spawn(move || {
            if let Err(e) = pipe::serve(handler) {
                eprintln!("tm-app: канал недоступен: {e}");
            }
        })
        .ok();
}

/* ------------------------------------------------------------------ main */

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tray = args.iter().any(|a| a == "--tray");
    let replace = args.iter().any(|a| a == "--replace");
    if !claim_instance(tray, replace) {
        return;
    }

    let service = Arc::new(Service::new(Engine::start(Duration::from_secs(1), default_store())));
    let engine = service.engine.clone();
    let _ = ENGINE.set(engine.clone());
    if log::set_logger(&EngineLog).is_ok() {
        log::set_max_level(log::LevelFilter::Warn);
    }

    let app = tauri::Builder::default()
        .manage(Ui { service: service.clone(), hidden_since: Mutex::new(None), maximize_on_show: AtomicBool::new(false), saving_memory: AtomicBool::new(false) })
        .invoke_handler(tauri::generate_handler![rpc, app_cmd])
        .on_window_event(|w, e| {
            // крестик прячет окно в трей; выход — из меню трея или «⋯ → Выйти»
            if w.label() != "main" {
                return;
            }
            match e {
                WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    hide_main(w.app_handle());
                }
                WindowEvent::Resized(_) => {
                    if let Some(ww) = main_window(w.app_handle()) {
                        let hidden = ww.is_minimized().unwrap_or(false) || !ww.is_visible().unwrap_or(true);
                        set_page_hidden(&ww, hidden);
                    }
                }
                _ => {}
            }
        })
        .setup(move |app| {
            let h = app.handle().clone();
            let open = MenuItemBuilder::with_id("open", "Открыть диспетчер").build(app)?;
            let quit = MenuItemBuilder::with_id("quit", "Выйти").build(app)?;
            let menu = MenuBuilder::new(app).item(&open).separator().item(&quit).build()?;
            TrayIconBuilder::with_id("main")
                .icon(tray_icon(&[0.0; 15]))
                .tooltip("Диспетчер задач")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| match e.id().as_ref() {
                    "open" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|t, e| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                        toggle_main(t.app_handle());
                    }
                })
                .build(app)?;

            start_pipe(h.clone(), service.clone());
            let e2 = engine.clone();
            let h2 = h.clone();
            std::thread::Builder::new().name("tm-tray".into()).spawn(move || tray_loop(h2, e2))?;
            build_main(&h, !tray)?;
            if tray {
                // страница грузится ещё какое-то время — сообщаем ей о скрытом окне, когда загрузится
                *h.state::<Ui>().hidden_since.lock().unwrap() = Some(Instant::now());
                let h3 = h.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(3));
                    if let Some(w) = main_window(&h3).filter(|w| !w.is_visible().unwrap_or(true)) {
                        set_page_hidden(&w, true);
                    }
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("не удалось запустить приложение");

    app.run(move |app, e| match e {
        // последнее окно закрылось (например, скрытое окно выгрузили) — остаёмся в трее
        RunEvent::ExitRequested { code: None, api, .. } => api.prevent_exit(),
        RunEvent::Exit => {
            if let Some(w) = main_window(app) {
                save_geometry(&w);
            }
            let s = &app.state::<Ui>().service;
            s.engine.stop();
            let _ = s.engine.save();
            tm_core::net_etw::shutdown();
        }
        _ => {}
    });
}
