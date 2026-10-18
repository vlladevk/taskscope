# tm — a task manager for Windows

A replacement for the Windows Task Manager. It stays fast and keeps responding under full load.
It shows who is using the CPU, memory, disk, GPU, network and Docker, and lets you end, suspend
or restart them. The CLI and an MCP server give AI agents the same features.

## What's inside

| File | What it is |
|---|---|
| `tm-app.exe` | The app: a window plus a tray icon with a live CPU chart. It holds the engine (a sample every second, a day of history) and the named pipe for the CLI |
| `tm.exe` | The CLI for the terminal and for agents. If the app is running, it gets data from it instantly; otherwise it samples by itself |

## Features

- Processes grouped by app. Short-lived helper processes (git, grep, compilers) are counted
  towards the app that starts them.
- Readable labels instead of `java`, `node`, `cmd`: the jar or main class, the script, the browser tab,
  the Claude Code session.
- 24 hours of history for apps, processes, GPUs and network adapters.
- A watcher that logs runaway loops, memory leaks and system overloads with the main culprit.
- Kernel pool by tag: driver memory that no process shows, with leak alarms and a search
  for the owning driver.
- Per-process network traffic (ETW, needs administrator rights) and connections and open ports.
- Process details: modules, threads, handles, environment, file signature and a VirusTotal link.
- "Who holds this file": find the processes that lock a file or anything in a folder.
- Windows services and Docker containers: list, start, stop, restart.
- Safe actions: critical Windows processes are protected. Programs with windows are asked to close
  first, so they can save their data. Restart keeps the same command line, folder, environment
  and rights.

## The app

- Run `tm-app.exe`. Starting it again just shows the window.
- The close button hides the window to the tray, and the engine keeps collecting history. After a minute
  in the tray, the window and its WebView2 are unloaded completely, so the app uses about 20 MB.
  The next opening takes about a second.
- Shortcuts:

  | Key | Action |
  |---|---|
  | `Esc` | Hide to the tray |
  | `Del` | End the process |
  | `Shift+Del` | End it with its children |
  | `Ctrl+F` | Search |
  | `Ctrl+J` | Bottom panel |
  | `Ctrl+Alt+B` | Right panel |
  | `Ctrl+B` | Resource list on the left |

- To open a full-window chart, click ⤢ in the bottom panel or double-click the chart.
- `⋯` → "Start with Windows" adds autostart to the tray (HKCU\…\Run). It is off by default.
- `⋯` → "Restart as administrator" shows the paths of all processes and **per-process network
  traffic**. Windows gives that data only to programs with administrator rights.
- Settings: `%LOCALAPPDATA%\tm\settings.json`. History: `%LOCALAPPDATA%\tm\history.bin`
  (saved every 10 minutes and on exit). Logs: `%LOCALAPPDATA%\tm\logs\`.

## CLI

```
tm sys                     summary: CPU, memory, GPUs, network
tm top                     who is loading the system now (--by cpu|mem|io|gpu|net)
tm apps / tm ps [name]     apps / processes
tm tree [target]           process tree with subtree totals
tm show <target>           everything about a process
tm kill|suspend|resume|restart <target> [--tree] [--app] [--dry-run]
tm prio <target> idle|below|normal|above|high
tm history --range 1h [--apps|--procs|--system|--net|--gpu] [--by …]
tm events                  log: hangs, leaks, overloads, actions
tm svc [filter]            Windows services (svc start|stop|restart <name>)
tm conns [target]          network connections and open ports
tm who <path>              who keeps a file or folder open
tm inspect <target> modules|threads|handles|env
tm sig <path|target>       file signature and SHA-256
tm docker [stop|start|restart|pause|unpause|kill <name>]
tm pool [--by size|growth] [--owners]   kernel pool by tag
tm daemon start|stop|status             background engine without the window
```

Every command accepts `--json`. A target is a PID, a name (`chrome`) or `PID:create_time` from the JSON output.
Run `tm help` for the full list.

## MCP (Claude Code and other agents)

```json
{ "mcpServers": { "tm": { "command": "C:\\path\\to\\tm.exe", "args": ["mcp"] } } }
```

Tools: `sys`, `top`, `apps`, `ps`, `tree`, `show`, `history`, `events`, `docker`, `pool`, `services`,
`connections`, `who`, `inspect`, `signature`.

The server is read-only by default. `tm mcp --allow-actions` adds `act`, `service_act` and container
actions. An agent can affect at most 20 processes at a time. It has no force mode, and it never sees process
environments.

## Building

You need Windows 10/11, the [Rust toolchain](https://rustup.rs/) with the MSVC target
(Visual Studio Build Tools with the "Desktop development with C++" workload) and the
WebView2 runtime. WebView2 is preinstalled on Windows 11.

```
cargo build --release
```

The binaries are written to `target\release\tm.exe` and `target\release\tm-app.exe`.

```
cargo test -p tm-core
```

UI development mode: `tm serve --root ui` serves the interface at http://127.0.0.1:5174. Actions on processes
are off unless you pass `--allow-actions`.

## Project layout

| Path | Contents |
|---|---|
| `crates/tm-core` | The core: sampling, tree, apps, history, watcher, GPUs, Docker, ETW, actions. `Service::call` is the single entry point |
| `crates/tm-cli` | The `tm` CLI, the MCP server and the dev server |
| `crates/tm-app` | The tray app (Tauri 2) |
| `ui/` | The interface (plain JavaScript) |

## License

[MIT](LICENSE). `ui/vendor/dockview-core.min.js` is [dockview](https://github.com/dockview/dockview)
8.3.1 and is also MIT-licensed.
