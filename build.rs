use std::env;

fn main() {
    let libs = ["cjose", "ssl", "jansson"];

    for lib in libs.iter() {
        let lib_dir_env_name = format!("{}_DIR", lib.to_uppercase());
        println!("cargo:rerun-if-env-changed={}", lib_dir_env_name);
        println!("cargo:rustc-link-lib={}={}", "dylib", lib);
        if let Ok(lib_dir) = env::var(lib_dir_env_name) {
            println!("cargo:rustc-link-search=native={}", lib_dir);
        }
    }
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rustc-link-lib={}={}", "dylib", "crypto"); // Bundled with openssl.
}