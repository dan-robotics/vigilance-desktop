fn main() {
    // Tell the linker to look in the project's root 'lib' folder for Packet.lib
    println!("cargo:rustc-link-search=native=../lib");
    tauri_build::build()
}
