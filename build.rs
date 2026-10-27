// En macOS compila native/se.swift como libreria estatica y la enlaza, para
// que el binario final hable con el Secure Enclave sin dependencias externas.
// En otras plataformas no hace nada.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=native/se.swift");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        other => other,
    }
    .to_string();
    let lib = out.join("liblockse.a");

    let status = Command::new("xcrun")
        .args(["swiftc", "-parse-as-library", "-emit-library", "-static", "-O"])
        .args(["-module-name", "LockSE"])
        .args(["-target", &format!("{arch}-apple-macos13")])
        .arg("native/se.swift")
        .arg("-o")
        .arg(&lib)
        .status()
        .expect("no se pudo ejecutar swiftc (instala las Command Line Tools de Xcode)");
    assert!(status.success(), "swiftc fallo compilando native/se.swift");

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=lockse");
    for fw in ["CryptoKit", "LocalAuthentication", "Security", "Foundation"] {
        println!("cargo:rustc-link-lib=framework={fw}");
    }

    // Runtime de Swift: viene con macOS, pero el linker necesita los .tbd del SDK.
    let sdk = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .expect("xcrun --show-sdk-path");
    let sdk = String::from_utf8(sdk.stdout).unwrap();
    println!("cargo:rustc-link-search=native={}/usr/lib/swift", sdk.trim());
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
