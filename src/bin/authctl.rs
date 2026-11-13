use auth_server::config::Config;
use auth_server::db::Db;
use std::env;
use std::io::{self, Write};
use std::process;

fn main() {
    let _ = load_dotenv(".env");

    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| {
        usage();
        process::exit(2);
    });

    match cmd.as_str() {
        "create-user" => {
            let username = args.next().unwrap_or_else(|| {
                eprintln!("usage: authctl create-user <username>");
                process::exit(2);
            });
            let password = read_password("Password: ").unwrap_or_else(|e| {
                eprintln!("{e}");
                process::exit(1);
            });
            let confirm = read_password("Confirm: ").unwrap_or_else(|e| {
                eprintln!("{e}");
                process::exit(1);
            });
            if password != confirm {
                eprintln!("passwords do not match");
                process::exit(1);
            }
            let cfg = config_or_exit();
            let db = Db::open(&cfg.db_path).unwrap_or_else(|e| {
                eprintln!("db error: {e}");
                process::exit(1);
            });
            match db.create_user(&username, &password) {
                Ok(user) => println!("created user {} ({})", user.username, user.id),
                Err(e) => {
                    eprintln!("create-user failed: {e}");
                    process::exit(1);
                }
            }
        }
        "rotate-keys" => {
            eprintln!(
                "Lab HS256: set a new AUTH_JWT_SECRET in the environment / unit file and restart auth-server.\n\
                 Existing access JWTs become invalid immediately; refresh tokens remain valid until expiry/revoke.\n\
                 Asymmetric key rotation (Ed25519/RS256) lands in a later revision."
            );
        }
        "help" | "-h" | "--help" => usage(),
        other => {
            eprintln!("unknown command: {other}");
            usage();
            process::exit(2);
        }
    }
}

fn config_or_exit() -> Config {
    Config::from_env().unwrap_or_else(|e| {
        eprintln!("config error: {e}");
        process::exit(1);
    })
}

fn usage() {
    eprintln!(
        "authctl — Command Center auth-server admin\n\n\
         Commands:\n\
           create-user <username>   Create a user (Argon2id)\n\
           rotate-keys              Print JWT secret rotation instructions\n\
           help                     Show this help\n\n\
         Uses AUTH_DB / AUTH_JWT_SECRET from the environment or .env"
    );
}

fn read_password(prompt: &str) -> io::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    // Scaffold: echo-visible password read. Prefer a TTY-hiding crate before production hardening.
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn load_dotenv(path: &str) -> io::Result<()> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
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
            if env::var_os(k).is_none() {
                env::set_var(k, v);
            }
        }
    }
    Ok(())
}
