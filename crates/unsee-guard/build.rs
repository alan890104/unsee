use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    println!("cargo:rerun-if-changed=interpose.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let source = PathBuf::from("interpose.c");

    if target_os == "macos" {
        let dylib_path = out_dir.join("unsee_interpose.dylib");

        let status = Command::new("cc")
            .args([
                "-dynamiclib",
                "-o",
                dylib_path.to_str().unwrap(),
                source.to_str().unwrap(),
            ])
            .status()
            .expect("failed to compile interpose.c");

        if !status.success() {
            panic!("failed to compile interpose.c into dylib");
        }

        println!(
            "cargo:rustc-env=UNSEE_DYLIB_PATH={}",
            dylib_path.display()
        );
    } else if target_os == "linux" {
        let so_path = out_dir.join("unsee_interpose.so");

        let status = Command::new("cc")
            .args([
                "-shared",
                "-fPIC",
                "-D_GNU_SOURCE",
                "-o",
                so_path.to_str().unwrap(),
                source.to_str().unwrap(),
                "-ldl",
            ])
            .status()
            .expect("failed to compile interpose.c");

        if !status.success() {
            panic!("failed to compile interpose.c into .so");
        }

        println!("cargo:rustc-env=UNSEE_DYLIB_PATH={}", so_path.display());
    } else {
        println!("cargo:rustc-env=UNSEE_DYLIB_PATH=");
    }
}
