// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sniffer;

/// Returns true if running in portable mode:
/// either --portable flag was passed, or a config/ folder exists next to the exe.
fn portable_mode() -> bool {
    if std::env::args().any(|a| a == "--portable") {
        return true;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("config").is_dir();
        }
    }
    false
}

/// Returns the path to config.json — portable-aware.
fn config_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    if portable_mode() {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let dir = exe.parent().ok_or("Cannot resolve exe directory")?;
        // Ensure config/ dir exists
        let config_dir = dir.join("config");
        std::fs::create_dir_all(&config_dir).map_err(|e| e.to_string())?;
        Ok(config_dir.join("config.json"))
    } else {
        use tauri::Manager;
        app.path()
            .resolve("config.json", tauri::path::BaseDirectory::Resource)
            .map_err(|e| e.to_string())
    }
}

#[tauri::command]
fn get_api_key(app: tauri::AppHandle) -> Result<String, String> {
    let path = config_path(&app)?;
    let config_str = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read config.json: {}", e))?;
    let config: serde_json::Value =
        serde_json::from_str(&config_str).map_err(|e| e.to_string())?;
    config["GEMINI_API_KEY"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "GEMINI_API_KEY not found in config.json".to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_api_key,
            sniffer::block_ip,
            sniffer::get_firewall_rules,
            sniffer::delete_firewall_rule,
            sniffer::get_interfaces,
            sniffer::set_capture_interface,
            sniffer::toggle_heuristics,
            sniffer::save_traffic_csv
        ])
        .setup(|app| {
            // Start the network probe with access to the v2 app handle
            sniffer::start_active_probe(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
