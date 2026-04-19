fn main() {
    println!("cargo:rustc-link-search=native=../lib");

    let mut attributes = tauri_build::Attributes::new();

    #[cfg(target_os = "windows")]
    {
        let windows_attributes = tauri_build::WindowsAttributes::new()
            .app_manifest(include_str!("vigilance.manifest"));
        attributes = attributes.windows_attributes(windows_attributes);
    }

    tauri_build::try_build(attributes).expect("Failed to run tauri-build");
}
