// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sniffer;

#[tauri::command]
fn get_api_key(app: tauri::AppHandle) -> Result<String, String> {
    use tauri::Manager;
    let resource_path = app
        .path()
        .resolve("config.json", tauri::path::BaseDirectory::Resource)
        .map_err(|e| e.to_string())?;
    let config_str = std::fs::read_to_string(&resource_path)
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
