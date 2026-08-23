use std::process::Command;

// Capture build provenance (git rev/date, toolchain, target) into env vars the
// crate reads via env! for the VERSION reply. Always emits every var, with an
// "unknown" fallback, so a non-git build (e.g. a source tarball) still compiles.
fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };

    let hash = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = match git(&["status", "--porcelain", "--untracked-files=no"]) {
        Some(s) if !s.is_empty() => "-dirty",
        _ => "",
    };
    let date = git(&["log", "-1", "--format=%cd", "--date=short"]).unwrap_or_else(|| "unknown".into());

    let rustc = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .and_then(|s| s.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_else(|| "unknown".into());

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());

    println!("cargo:rustc-env=ECHOIRCD_GIT_HASH={hash}");
    println!("cargo:rustc-env=ECHOIRCD_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=ECHOIRCD_COMMIT_DATE={date}");
    println!("cargo:rustc-env=ECHOIRCD_RUSTC={rustc}");
    println!("cargo:rustc-env=ECHOIRCD_TARGET={target}");
}
