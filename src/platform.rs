//! How an installed server starts: a Windows service, or at login with a taskbar icon.
//!
//! Linux uses a user systemd unit for the service choice and an autostart entry for login.
//! The taskbar icon is a Windows tray icon. Login on Linux just starts the server.

use std::path::{Path, PathBuf};

pub const SERVICE_NAME: &str = "CommandCenterAuth";
pub const STARTUP_VALUE_NAME: &str = "Command Center auth-server";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupMode {
    Service,
    Login,
}

impl StartupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Login => "login",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "service" | "windows-service" => Ok(Self::Service),
            "login" | "tray" | "taskbar" | "sign-in" => Ok(Self::Login),
            other => Err(format!(
                "startup must be service or login (got {other}). Service runs in the background. Login starts when you sign in and shows a taskbar icon."
            )),
        }
    }
}

pub fn register_startup(
    mode: StartupMode,
    exe: &Path,
    home: &Path,
    server_dir: &Path,
) -> Result<(), String> {
    unregister_startup()?;
    match mode {
        StartupMode::Service => register_service(exe, home, server_dir),
        StartupMode::Login => register_login(exe, home, server_dir),
    }
}

pub fn unregister_startup() -> Result<(), String> {
    let _ = remove_service();
    let _ = remove_login();
    Ok(())
}

pub fn start_service() -> Result<(), String> {
    #[cfg(windows)]
    {
        return start_windows_service();
    }
    #[cfg(not(windows))]
    {
        let status = std::process::Command::new("systemctl")
            .args(["--user", "start", "command-center-auth.service"])
            .status()
            .map_err(|err| format!("could not start the user service: {err}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("could not start the auth-server user service".into())
        }
    }
}

pub fn stop_service() -> Result<(), String> {
    #[cfg(windows)]
    {
        return stop_windows_service();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "stop", "command-center-auth.service"])
            .status();
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn run_service_dispatcher() -> Result<(), String> {
    Err("A Windows service is only available on Windows.".into())
}

/// Windows: tray icon and a message loop. Other systems: the caller runs the server itself.
#[cfg(windows)]
pub fn run_tray(open_url: &str) -> Result<(), String> {
    use tray_icon::menu::{Menu, MenuEvent, MenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    let menu = Menu::new();
    let open = MenuItem::with_id("open", "Open server settings", true, None);
    let quit = MenuItem::with_id("quit", "Quit", true, None);
    menu.append(&open).map_err(|err| err.to_string())?;
    menu.append(&quit).map_err(|err| err.to_string())?;
    let icon = Icon::from_rgba(tray_pixels(), 32, 32).map_err(|err| err.to_string())?;
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Command Center server")
        .with_icon(icon)
        .build()
        .map_err(|err| err.to_string())?;

    let open_url = open_url.to_string();
    let receiver = MenuEvent::receiver();
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            DispatchMessageW, GetMessageW, TranslateMessage, MSG,
        };
        let mut msg = std::mem::zeroed::<MSG>();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            while let Ok(event) = receiver.try_recv() {
                if event.id == open.id().clone() {
                    open_in_browser(&open_url);
                } else if event.id == quit.id().clone() {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn run_service_dispatcher() -> Result<(), String> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|err| format!("Windows service failed to start: {err}"))
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_handler = Arc::clone(&stop);
    let status = match service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop_for_handler.store(true, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) {
        Ok(status) => status,
        Err(_) => return,
    };
    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    };
    let _ = status.set_service_status(running);
    // The service control manager passes its own start arguments, which are not
    // the install path. The process command line is `--run-service --home <dir>`.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stop_for_server = Arc::clone(&stop);
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => {
                stop_for_server.store(true, Ordering::SeqCst);
                return;
            }
        };
        runtime.block_on(async {
            if let Err(err) = crate::serve_from_args(&args).await {
                eprintln!("auth-server: {err}");
            }
        });
        stop_for_server.store(true, Ordering::SeqCst);
    });
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let stopped = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    };
    let _ = status.set_service_status(stopped);
}

#[cfg(windows)]
fn register_service(exe: &Path, home: &Path, _server_dir: &Path) -> Result<(), String> {
    match try_register_service(exe, home) {
        Ok(()) => Ok(()),
        Err(err) if access_denied(&err) => elevate_service_command(exe, home, "--install-service"),
        Err(err) => Err(err),
    }
}

#[cfg(not(windows))]
fn register_service(exe: &Path, _home: &Path, server_dir: &Path) -> Result<(), String> {
    install_systemd(server_dir, exe)
}

#[cfg(windows)]
fn register_login(exe: &Path, home: &Path, server_dir: &Path) -> Result<(), String> {
    let vbs = server_dir.join("start-tray.vbs");
    let script = format!(
        "CreateObject(\"Wscript.Shell\").Run \"\"\"{exe}\"\" --tray --home \"\"{home}\"\"\", 0, False\r\n",
        exe = exe.display(),
        home = home.display(),
    );
    std::fs::write(&vbs, script).map_err(|err| format!("could not write {}: {err}", vbs.display()))?;
    let command = format!("wscript.exe //B \"{}\"", vbs.display());
    let status = std::process::Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            STARTUP_VALUE_NAME,
            "/t",
            "REG_SZ",
            "/d",
            &command,
            "/f",
        ])
        .status()
        .map_err(|err| format!("could not set the login startup entry: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("could not set the server to start when you sign in".into())
    }
}

#[cfg(not(windows))]
fn register_login(exe: &Path, home: &Path, _server_dir: &Path) -> Result<(), String> {
    let dir = autostart_dir()?;
    std::fs::create_dir_all(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let path = dir.join("command-center-auth.desktop");
    let body = format!(
        "[Desktop Entry]\nType=Application\nName=Command Center server\nExec=\"{exe}\" --tray --home \"{home}\"\nX-GNOME-Autostart-enabled=true\n",
        exe = exe.display(),
        home = home.display(),
    );
    std::fs::write(&path, body).map_err(|err| format!("could not write {}: {err}", path.display()))
}

#[cfg(windows)]
fn remove_service() -> Result<(), String> {
    match try_remove_service() {
        Ok(()) => Ok(()),
        Err(err) if access_denied(&err) => {
            let exe = std::env::current_exe().map_err(|err| err.to_string())?;
            elevate_service_command(&exe, Path::new("."), "--uninstall-service")
        }
        Err(err) => Err(err),
    }
}

#[cfg(not(windows))]
fn remove_service() -> Result<(), String> {
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "command-center-auth.service"])
        .status();
    if let Ok(dir) = systemd_user_dir() {
        let _ = std::fs::remove_file(dir.join("command-center-auth.service"));
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
    }
    Ok(())
}

#[cfg(windows)]
fn remove_login() -> Result<(), String> {
    let _ = std::process::Command::new("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            STARTUP_VALUE_NAME,
            "/f",
        ])
        .status();
    let _ = std::process::Command::new("schtasks")
        .args(["/Delete", "/F", "/TN", STARTUP_VALUE_NAME])
        .status();
    Ok(())
}

#[cfg(not(windows))]
fn remove_login() -> Result<(), String> {
    if let Ok(dir) = autostart_dir() {
        let _ = std::fs::remove_file(dir.join("command-center-auth.desktop"));
    }
    Ok(())
}

#[cfg(windows)]
fn try_register_service(exe: &Path, home: &Path) -> Result<(), String> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(service_err)?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Command Center auth-server"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![
            OsString::from("--run-service"),
            OsString::from("--home"),
            home.as_os_str().to_os_string(),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::DELETE;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(existing) => {
            existing.change_config(&info).map_err(service_err)?;
            existing
        }
        Err(_) => manager.create_service(&info, access).map_err(service_err)?,
    };
    let _ = service.set_description(
        "Command Center account server. The server admin is for these settings, not a board login.",
    );
    let _ = service.start::<&str>(&[]);
    Ok(())
}

#[cfg(windows)]
fn try_remove_service() -> Result<(), String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(service_err)?;
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE)
    {
        Ok(service) => service,
        Err(err) => {
            let text = service_err(err);
            if text.to_lowercase().contains("does not exist") || text.contains("1060") {
                return Ok(());
            }
            return Err(text);
        }
    };
    let _ = service.stop();
    service.delete().map_err(service_err)?;
    Ok(())
}

#[cfg(windows)]
fn start_windows_service() -> Result<(), String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(service_err)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(service_err)?;
    service.start::<&str>(&[]).map_err(service_err)?;
    Ok(())
}

#[cfg(windows)]
fn stop_windows_service() -> Result<(), String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(service_err)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::STOP) {
        Ok(service) => {
            let _ = service.stop();
            Ok(())
        }
        Err(err) => {
            let text = service_err(err);
            if text.contains("1060") || text.to_lowercase().contains("does not exist") {
                Ok(())
            } else {
                Err(text)
            }
        }
    }
}

#[cfg(windows)]
fn elevate_service_command(exe: &Path, home: &Path, flag: &str) -> Result<(), String> {
    let script = std::env::temp_dir().join(format!(
        "cc-auth-elevate-{}-{flag}.ps1",
        std::process::id()
    ));
    let body = format!(
        "Start-Process -FilePath '{exe}' -ArgumentList '{flag}','--home','{home}' -Verb RunAs -Wait\n",
        exe = exe.display().to_string().replace('\'', "''"),
        home = home.display().to_string().replace('\'', "''"),
        flag = flag,
    );
    std::fs::write(&script, &body).map_err(|err| err.to_string())?;
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &script.display().to_string(),
        ])
        .status()
        .map_err(|err| format!("could not ask Windows for administrator approval: {err}"))?;
    let _ = std::fs::remove_file(&script);
    if status.success() {
        Ok(())
    } else {
        Err(
            "Windows did not approve the service change. You can choose start at login instead."
                .into(),
        )
    }
}

#[cfg(windows)]
fn service_err(err: windows_service::Error) -> String {
    let text = err.to_string();
    if access_denied(&text) {
        format!("access denied: {text}")
    } else {
        text
    }
}

#[cfg(windows)]
fn access_denied(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("access denied") || lower.contains("os error 5") || lower.contains("error 5")
}

#[cfg(windows)]
fn tray_pixels() -> Vec<u8> {
    let mut pixels = vec![0u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let dx = x as i32 - 16;
            let dy = y as i32 - 16;
            if dx * dx + dy * dy <= 13 * 13 {
                let index = (y * 32 + x) * 4;
                pixels[index] = 0x3d;
                pixels[index + 1] = 0x9c;
                pixels[index + 2] = 0xf0;
                pixels[index + 3] = 255;
            }
        }
    }
    pixels
}

#[cfg(windows)]
fn open_in_browser(url: &str) {
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
}

#[cfg(not(windows))]
fn install_systemd(server_dir: &Path, exe: &Path) -> Result<(), String> {
    let unit_dir = systemd_user_dir()?;
    std::fs::create_dir_all(&unit_dir)
        .map_err(|err| format!("could not create {}: {err}", unit_dir.display()))?;
    let unit = format!(
        "\
[Unit]\n\
Description=Command Center auth-server\n\
After=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
WorkingDirectory={dir}\n\
ExecStart={exe}\n\
Restart=on-failure\n\
RestartSec=3\n\
\n\
[Install]\n\
WantedBy=default.target\n\
",
        dir = server_dir.display(),
        exe = exe.display(),
    );
    let path = unit_dir.join("command-center-auth.service");
    std::fs::write(&path, unit).map_err(|err| format!("could not write {}: {err}", path.display()))?;
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "enable", "command-center-auth.service"])
        .status();
    Ok(())
}

#[cfg(not(windows))]
fn systemd_user_dir() -> Result<PathBuf, String> {
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        if !config.is_empty() {
            return Ok(PathBuf::from(config).join("systemd/user"));
        }
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set; cannot write a user service")?;
    Ok(PathBuf::from(home).join(".config/systemd/user"))
}

#[cfg(not(windows))]
fn autostart_dir() -> Result<PathBuf, String> {
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        if !config.is_empty() {
            return Ok(PathBuf::from(config).join("autostart"));
        }
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set; cannot write an autostart entry")?;
    Ok(PathBuf::from(home).join(".config/autostart"))
}
