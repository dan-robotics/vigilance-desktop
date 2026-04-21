fn main() {
    println!("cargo:rustc-link-search=native=../lib");

    #[cfg(target_os = "windows")]
    let attributes = {
        let windows_attributes = tauri_build::WindowsAttributes::new()
            .app_manifest(include_str!("vigilance.manifest"));
        tauri_build::Attributes::new().windows_attributes(windows_attributes)
    };
    #[cfg(not(target_os = "windows"))]
    let attributes = tauri_build::Attributes::new();

    tauri_build::try_build(attributes).expect("Failed to run tauri-build");
}
