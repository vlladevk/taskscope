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
use std::sync::atomic::{AtomicU32, Ordering};
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
/// Спрятанное в трей дольше этого окно закрывается целиком: WebView2 отдаёт всю свою память.
/// Движок и трей продолжают работать, следующее открытие займёт около секунды.
const DROP_WINDOW_AFTER: Duration = Duration::from_secs(60);

struct Ui {
    service: Arc<Service>,
    hidden_since: Mutex<Option<Instant>>,
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

/// Живое главное окно. Если создание WebView2 сорвалось, Tauri оставляет в своём списке мёртвое
/// окно, которое не отвечает на запросы, — его не считаем.
fn main_window(app: &AppHandle) -> Option<WebviewWindow> {
    app.webview_windows()
        .into_iter()
        .filter(|(label, _)| label.starts_with("main"))
        .map(|(_, w)| w)
        .find(|w| w.is_visible().is_ok())
}

/// Имя может остаться за мёртвым окном, поэтому каждое новое окно получает своё: main, main-1, …
static NEXT_WINDOW: AtomicU32 = AtomicU32::new(0);

/// Окно создаётся скрытым и показывается, только когда WebView2 уже встроен. Если встраивать его
/// в окно, которое в этот момент показывается и разворачивается, WebView2 то и дело падает с
/// ERROR_NOT_ENOUGH_QUOTA (0x80070718); скрытые окна создаются без сбоев. Вызывать только
/// в главном потоке: там build() возвращается, когда WebView2 уже создан.
fn build_main(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let g = load_geometry().filter(|g| on_screen(app, g));
    let n = NEXT_WINDOW.fetch_add(1, Ordering::Relaxed);
    let label = if n == 0 { "main".to_string() } else { format!("main-{n}") };
    let mut b = WebviewWindowBuilder::new(app, label, WebviewUrl::App("index.html".into()))
        .title("Диспетчер задач")
        .inner_size(g.map_or(1360.0, |g| g.w.max(900.0)), g.map_or(860.0, |g| g.h.max(560.0)))
        .min_inner_size(900.0, 560.0)
        .theme(Some(tauri::Theme::Dark))
        .background_color(tauri::window::Color(32, 32, 32, 255))
        .visible(false);
    b = match g {
        Some(g) => b.position(g.x, g.y),
        None => b.center(),
    };
    let w = b.build()?;
    if g.is_some_and(|g| g.max) {
        let _ = w.maximize();
    }
    Ok(w)
}

/// WebView2 не считает страницу скрытой, когда окно спрятано в трей или свёрнуто, —
/// сообщаем сами: скрытая страница не опрашивает движок и ничего не рисует.
fn set_page_hidden(w: &WebviewWindow, hidden: bool) {
    let _ = w.eval(format!("window.__tmHidden={hidden}"));
}

fn reveal(w: &WebviewWindow) {
    let _ = w.unminimize();
    let _ = w.show();
    set_page_hidden(w, false);
    let _ = w.set_focus();
}

fn show_main(app: &AppHandle) {
    *app.state::<Ui>().hidden_since.lock().unwrap() = None;
    match main_window(app) {
        Some(w) => reveal(&w),
        None => open_main(app, 1),
    }
}

/// Создаёт и показывает окно. Строим в главном потоке отдельной задачей цикла событий: из других
/// потоков Tauri создаёт окно асинхронно и при сбое лишь пишет в свой журнал, а прямо в обработчике
/// трея создание WebView2 может зависнуть. Проверяем, что окно появилось, и при сбое пробуем ещё.
fn open_main(app: &AppHandle, attempt: u32) {
    let log = |a: &AppHandle, lvl: &str, s: String| a.state::<Ui>().service.engine.log(lvl, s, None);
    let a = app.clone();
    let posted = app.run_on_main_thread(move || {
        if main_window(&a).is_some() {
            return;
        }
        match build_main(&a) {
            Ok(w) if w.is_visible().is_ok() => reveal(&w),
            Ok(_) => {}
            Err(e) => log(&a, "red", format!("Не удалось открыть окно: {e}")),
        }
    });
    if let Err(e) = posted {
        return log(app, "red", format!("Не удалось открыть окно: {e}"));
    }
    let a = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        if main_window(&a).is_some() {
            return;
        }
        if attempt < 3 {
            log(&a, "yel", format!("Окно не открылось с {attempt}-й попытки — пробую ещё раз"));
            open_main(&a, attempt + 1);
        } else {
            relaunch_with_window(&a);
        }
    });
}

/// Крайний случай: окно не создаётся. Перезапускаемся — новый экземпляр сам попросит этот
/// завершиться (--replace), история сохранится.
fn relaunch_with_window(app: &AppHandle) {
    let engine = &app.state::<Ui>().service.engine;
    engine.log("red", "Окно так и не открылось — перезапускаю приложение (причина в записях журнала выше)".into(), None);
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
        // долго спрятанное окно закрываем целиком — вместе с памятью WebView2
        let ui = app.state::<Ui>();
        let stale = ui.hidden_since.lock().unwrap().is_some_and(|t| t.elapsed() >= DROP_WINDOW_AFTER);
        if stale {
            *ui.hidden_since.lock().unwrap() = None;
            if let Some(w) = main_window(&app) {
                let _ = w.destroy();
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
            let parent = main_window(&app).and_then(|w| w.hwnd().ok()).map_or(0, |h| h.0 as isize);
            system::shell_execute_from(parent, "runas", &exe.display().to_string(), "--replace").map_err(|_| "запуск от администратора отменён".to_string())?;
        }
        // «включён» — только если Windows его действительно запустит: выключенный в «Автозагрузке»
        // диспетчера задач автозапуск остаётся в Run, но не работает
        "autostart_get" => return Ok(json!(system::autostart_enabled(AUTOSTART_NAME))),
        "autostart_set" => {
            let on = arg.as_ref().and_then(Value::as_bool).unwrap_or(false);
            let c = autostart_cmd();
            system::autostart_set(AUTOSTART_NAME, if on { c.as_deref() } else { None }).map_err(|e| e.to_string())?;
            return Ok(json!(system::autostart_enabled(AUTOSTART_NAME)));
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

/// Вызов по каналу с повторами: другой экземпляр может ещё запускаться и не слушать канал.
fn call_retry(method: &str, secs: u64) -> bool {
    let until = Instant::now() + Duration::from_secs(secs);
    loop {
        // «неизвестный метод» — отвечает `tm daemon`, которого приложение вот-вот сменит: ждём приложение
        match pipe::call(method, Value::Null, Duration::from_secs(2)) {
            Ok(_) => return true,
            Err(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(150)),
            Err(_) => return false,
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
        "app_quit" | "shutdown" => {
            let a = app.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                a.exit(0);
            });
            Ok(json!(true))
        }
        m if service::is_local_only(m) => Err("действия через канал не выполняются: клиент выполняет их сам, со своими правами".into()),
        m => service.call(m, p),
    });
    std::thread::Builder::new()
        .name("tm-pipe-server".into())
        .spawn(move || {
            if let Err(e) = pipe::serve(handler) {
                eprintln!("tm-app: канал недоступен: {e}");
                tm_core::logs::error(format!("канал недоступен: {e}"));
            }
        })
        .ok();
}

/* ------------------------------------------------------------------ main */

fn main() {
    // журнал ошибок и паник: у приложения в трее нет консоли
    tm_core::logs::init("tm-app");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tray = args.iter().any(|a| a == "--tray");
    let replace = args.iter().any(|a| a == "--replace");
    // замок держим до конца процесса: пока он наш, второй экземпляр главным не станет
    let lock = system::InstanceLock::acquire("Local\\tm-app-instance");
    if let Some((lock, false)) = &lock {
        // экземпляр уже есть, но мог ещё не открыть канал (запущены в одну секунду) — ждём его
        if !replace {
            call_retry(if tray { "app_hello" } else { "app_show" }, 10);
            return;
        }
        call_retry("app_quit", 10);
        if !lock.wait(Duration::from_secs(10)) {
            return;
        }
    }
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
        .manage(Ui { service: service.clone(), hidden_since: Mutex::new(None) })
        .invoke_handler(tauri::generate_handler![rpc, app_cmd])
        .on_window_event(|w, e| {
            // крестик прячет окно в трей; выход — из меню трея или «⋯ → Выйти»
            if !w.label().starts_with("main") {
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
            // в трее окна нет вовсе — оно создаётся при первом открытии
            if !tray {
                open_main(&h, 1);
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
            tm_core::file_etw::shutdown();
        }
        _ => {}
    });
}
