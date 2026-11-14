use auth_server::backup;
use auth_server::config::{self, Config, ServerMode};
use auth_server::db::Db;
use auth_server::install::{self, InstallRequest};
use auth_server::platform::{self, StartupMode};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use tracing_subscriber::EnvFilter;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Some(command) = args.first().map(String::as_str) {
        match command {
            "--install" => {
                if let Err(err) = run_install(&args[1..]) {
                    eprintln!("auth-server install failed: {err}");
                    process::exit(1);
                }
                return;
            }
            "--uninstall" => {
                let home = flag(&args[1..], "--home")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));
                if let Err(err) = install::uninstall(&home) {
                    eprintln!("auth-server uninstall failed: {err}");
                    process::exit(1);
                }
                return;
            }
            "--install-service" => {
                let home = flag(&args[1..], "--home").unwrap_or(".");
                let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("auth-server"));
                if let Err(err) = platform::register_startup(
                    StartupMode::Service,
                    &exe,
                    Path::new(home),
                    &Path::new(home).join("server"),
                ) {
                    eprintln!("auth-server service install failed: {err}");
                    process::exit(1);
                }
                return;
            }
            "--uninstall-service" => {
                if let Err(err) = platform::unregister_startup() {
                    eprintln!("auth-server service removal failed: {err}");
                    process::exit(1);
                }
                return;
            }
            "--service-start" => {
                if let Err(err) = platform::start_service() {
                    eprintln!("auth-server service start failed: {err}");
                    process::exit(1);
                }
                return;
            }
            "--service-stop" => {
                if let Err(err) = platform::stop_service() {
                    eprintln!("auth-server service stop failed: {err}");
                    process::exit(1);
                }
                return;
            }
            "--run-service" => {
                if let Err(err) = platform::run_service_dispatcher() {
                    eprintln!("{err}");
                    process::exit(1);
                }
                return;
            }
            "--tray" => {
                init_tracing();
                prepare_home(&args[1..]);
                let url = admin_url();
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                #[cfg(windows)]
                {
                    runtime.spawn(async {
                        if let Err(err) = auth_server::serve_from_args(&Vec::new()).await {
                            eprintln!("auth-server: {err}");
                        }
                    });
                    if let Err(err) = platform::run_tray(&url) {
                        eprintln!("auth-server tray failed: {err}");
                        process::exit(1);
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = url;
                    runtime.block_on(async {
                        if let Err(err) = auth_server::serve_from_args(&Vec::new()).await {
                            eprintln!("auth-server: {err}");
                            process::exit(1);
                        }
                    });
                }
                return;
            }
            "--backup-export" => {
                if let Err(err) = run_backup_export(&args[1..]) {
                    eprintln!("auth-server backup export failed: {err}");
                    process::exit(1);
                }
                return;
            }
            "--backup-import" => {
                if let Err(err) = run_backup_import(&args[1..]) {
                    eprintln!("auth-server backup import failed: {err}");
                    process::exit(1);
                }
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            other if other.starts_with('-') => {
                eprintln!("unknown option: {other}");
                print_help();
                process::exit(2);
            }
            _ => {}
        }
    }

    init_tracing();

    // Load .env from the working directory, then from the binary's directory.
    // Existing variables win, so a service manager can still override the file.
    let _ = config::load_dotenv(Path::new(".env"));
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = config::load_dotenv(&dir.join(".env"));
        }
    }

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("auth-server config error: {e}");
            process::exit(1);
        }
    };
    write_pid(&cfg.db_path);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    if let Err(err) = runtime.block_on(auth_server::serve(cfg)) {
        eprintln!("{err}");
        process::exit(1);
    }
}

fn run_install(args: &[String]) -> Result<(), String> {
    let home = flag(args, "--home").ok_or("missing --home (Command Center config directory)")?;
    let role = ServerMode::parse(flag(args, "--role").unwrap_or("device"))?;
    let port: u16 = flag(args, "--port")
        .unwrap_or("8080")
        .parse()
        .map_err(|_| "port must be a number from 1 to 65535".to_string())?;
    if port == 0 {
        return Err("port must be a number from 1 to 65535".into());
    }
    let exe = env::current_exe().map_err(|err| format!("could not find this binary: {err}"))?;
    let startup = StartupMode::parse(flag(args, "--startup").unwrap_or("login"))?;
    let (admin_username, admin_password) = read_admin_file(flag(args, "--admin-file"))?;
    let dir = install::install(&InstallRequest {
        home: PathBuf::from(home),
        role,
        secret_store: has(args, "--secret-store"),
        port,
        autostart: has(args, "--autostart"),
        startup,
        exe,
        admin_username,
        admin_password,
    })?;
    println!("{}", dir.display());
    Ok(())
}

fn run_backup_export(args: &[String]) -> Result<(), String> {
    let file = flag(args, "--file").ok_or("missing --file")?;
    let db = open_from_args(args)?;
    backup::export_path(&db, Path::new(file))?;
    println!("{file}");
    Ok(())
}

fn run_backup_import(args: &[String]) -> Result<(), String> {
    if !has(args, "--yes") {
        return Err("backup import replaces accounts on this server. Pass --yes to do that.".into());
    }
    let file = flag(args, "--file").ok_or("missing --file")?;
    let db = open_from_args(args)?;
    backup::import_path(&db, Path::new(file))?;
    println!("imported {file}");
    Ok(())
}

fn open_from_args(args: &[String]) -> Result<Db, String> {
    let db_path = if let Some(home) = flag(args, "--home") {
        let env_path = PathBuf::from(home).join("server").join(".env");
        let _ = config::load_dotenv(&env_path);
        env::var("AUTH_DB").map(PathBuf::from).unwrap_or_else(|_| {
            PathBuf::from(home).join("server").join("data").join("auth-server.db")
        })
    } else if let Ok(path) = env::var("AUTH_DB") {
        PathBuf::from(path)
    } else {
        PathBuf::from("./data/auth-server.db")
    };
    Db::open(&db_path).map_err(|err| format!("db error: {err}"))
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn write_pid(db_path: &Path) {
    let Some(data_dir) = db_path.parent() else {
        return;
    };
    let Some(server_dir) = data_dir.parent() else {
        return;
    };
    let _ = std::fs::write(server_dir.join("auth-server.pid"), process::id().to_string());
}

fn print_help() {
    eprintln!(
        "\
auth-server — Command Center account server

Run with no arguments to listen (AUTH_BIND, AUTH_DB, AUTH_JWT_SECRET, AUTH_MODE).

  --install --home <dir> [--role device|shared] [--port 8080] [--secret-store]
            [--startup service|login] [--admin-file <path>] [--autostart]
      Write the server files for this computer. The admin file's first line is the
      server admin username and the rest is the password. That account is for the
      server and its settings, not a Command Center board login. service runs as a
      Windows service. login starts when you sign in and shows a taskbar icon.
  --uninstall --home <dir>
      Remove the Windows service and the login startup entry.
  --backup-export --file <path> [--home <dir>]
      Write a backup of accounts, boards, and any stored secrets.
  --backup-import --file <path> --yes [--home <dir>]
      Replace this server's accounts with a backup. Stop the server first.
"
    );
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();
}

fn prepare_home(args: &[String]) {
    if let Some(home) = flag(args, "--home") {
        let _ = config::load_dotenv(&Path::new(home).join("server").join(".env"));
    }
}

fn admin_url() -> String {
    let bind = env::var("AUTH_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let port = bind
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or(8080);
    format!("http://127.0.0.1:{port}/admin")
}

fn read_admin_file(path: Option<&str>) -> Result<(Option<String>, Option<String>), String> {
    let Some(path) = path else {
        return Ok((None, None));
    };
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("could not read the server admin file: {err}"))?;
    let _ = fs::write(path, "");
    let _ = fs::remove_file(path);
    let mut lines = raw.lines();
    let username = lines.next().unwrap_or("").trim().to_string();
    let password = lines.collect::<Vec<_>>().join("\n");
    if username.is_empty() || password.is_empty() {
        return Err(
            "The server admin file needs a username and a password. This account is for the server and its settings, not a Command Center board login.".into(),
        );
    }
    Ok((Some(username), Some(password)))
}
