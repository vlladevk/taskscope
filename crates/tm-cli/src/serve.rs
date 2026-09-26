//! `tm serve` — режим разработки: отдаёт интерфейс из папки `ui` и принимает
//! `POST /rpc {method, params}` → `Service::call`. Только 127.0.0.1.
//! Действия над процессами выключены, пока не передан `--allow-actions`,
//! а запросы с чужих страниц (другой Origin) отклоняются. Движок здесь — второй экземпляр только
//! для чтения: историю на диск не пишет и сеанс ETW не запускает (он общий с приложением).
//! Файлы отдаются только из папки ui.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Value};
use tm_core::Service;

pub fn run(service: Arc<Service>, root: PathBuf, port: u16, allow_actions: bool) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("tm serve: http://127.0.0.1:{port}/  (папка {}, действия {})", root.display(), if allow_actions { "разрешены" } else { "выключены" });
    for conn in listener.incoming().flatten() {
        let (service, root) = (service.clone(), root.clone());
        std::thread::spawn(move || {
            let _ = handle(conn, &service, &root, port, allow_actions);
        });
    }
    Ok(())
}

fn handle(mut conn: TcpStream, service: &Service, root: &Path, port: u16, allow_actions: bool) -> std::io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let (mut len, mut origin) = (0usize, None::<String>);
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        let (k, v) = h.split_once(':').unwrap_or((&h, ""));
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => len = v.trim().parse().unwrap_or(0),
            "origin" => origin = Some(v.trim().to_string()),
            _ => {}
        }
    }
    if method == "POST" && path == "/rpc" {
        let ok_origin = origin.as_deref().map_or(true, |o| o == format!("http://127.0.0.1:{port}") || o == format!("http://localhost:{port}"));
        let mut body = vec![0u8; len.min(4 << 20)];
        reader.read_exact(&mut body)?;
        let resp = if !ok_origin {
            json!({ "error": "запрос с чужой страницы отклонён" })
        } else {
            match serde_json::from_slice::<Value>(&body) {
                Ok(req) => {
                    let m = req["method"].as_str().unwrap_or("");
                    // пробный прогон ничего не меняет — окно подтверждения работает и в режиме чтения
                    let dry = m == "act" && req["params"]["dry_run"] == true;
                    if tm_core::service::is_mutating(m) && !allow_actions && !dry {
                        json!({ "error": "в режиме разработки действия выключены (tm serve --allow-actions)" })
                    } else {
                        match service.call(m, &req["params"]) {
                            Ok(v) => json!({ "result": v }),
                            Err(e) => json!({ "error": e }),
                        }
                    }
                }
                Err(e) => json!({ "error": e.to_string() }),
            }
        };
        return reply(&mut conn, 200, "application/json; charset=utf-8", &serde_json::to_vec(&resp).unwrap_or_default());
    }
    if method != "GET" {
        return reply(&mut conn, 405, "text/plain", b"method not allowed");
    }
    let rel = path.split('?').next().unwrap_or("/").trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    // только обычные имена внутри папки ui: без «..», дисков («C:»), корня и UNC-путей
    let normal = Path::new(rel).components().all(|c| matches!(c, std::path::Component::Normal(_)));
    let file = root.join(rel);
    // и после разрешения ссылок файл всё ещё внутри папки
    let inside = match (file.canonicalize(), root.canonicalize()) {
        (Ok(f), Ok(r)) => f.starts_with(r),
        _ => false,
    };
    if !normal || rel.contains(':') || !inside {
        return reply(&mut conn, if normal && !rel.contains(':') { 404 } else { 403 }, "text/plain", b"forbidden or not found");
    }
    match std::fs::read(&file) {
        Ok(data) => {
            let ct = match rel.rsplit('.').next().unwrap_or("") {
                "html" => "text/html; charset=utf-8",
                "js" => "text/javascript; charset=utf-8",
                "css" => "text/css; charset=utf-8",
                "png" => "image/png",
                "svg" => "image/svg+xml",
                "ico" => "image/x-icon",
                _ => "application/octet-stream",
            };
            reply(&mut conn, 200, ct, &data)
        }
        Err(_) => reply(&mut conn, 404, "text/plain", b"not found"),
    }
}

fn reply(conn: &mut TcpStream, code: u16, ct: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {code} OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    // одной записью и без алгоритма Нейгла: иначе Windows придерживает ответ на ~200–300 мс
    let _ = conn.set_nodelay(true);
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    conn.write_all(&out)
}
