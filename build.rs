// The target triple is only visible to a build script, and `--version` reports
// it so a downloaded binary can be identified. Nothing else here.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=BARE_SERVER_TARGET={target}");
}
