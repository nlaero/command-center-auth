use auth_server::config::Config;
use auth_server::db::Db;
use auth_server::rate_limit::LoginRateLimiter;
use auth_server::{router, AppState};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // Load .env if present (simple KEY=VALUE lines; ignore comments/blank).
    let _ = load_dotenv(".env");

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("auth-server config error: {e}");
            std::process::exit(1);
        }
    };

    let db = match Db::open(&cfg.db_path) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("auth-server db error: {e}");
            std::process::exit(1);
        }
    };

    let state = AppState {
        db: Arc::new(db),
        cfg: Arc::new(cfg.clone()),
        limiter: Arc::new(LoginRateLimiter::default()),
    };

    let app = router(state).layer(tower_http::trace::TraceLayer::new_for_http());
    let listener = match tokio::net::TcpListener::bind(&cfg.bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("auth-server bind {} failed: {e}", cfg.bind);
            std::process::exit(1);
        }
    };

    tracing::info!(bind = %cfg.bind, db = %cfg.db_path.display(), "auth-server listening");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("auth-server exited: {e}");
        std::process::exit(1);
    }
}

fn load_dotenv(path: &str) -> std::io::Result<()> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            if std::env::var_os(k).is_none() {
                std::env::set_var(k, v);
            }
        }
    }
    Ok(())
}
