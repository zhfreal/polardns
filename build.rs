use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    emit_git_rerun_hints();

    let commit = git_output(["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let commit = if commit != "unknown" && git_worktree_is_dirty() {
        format!("{commit}-dirty")
    } else {
        commit
    };

    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| {
            k.strip_prefix("CARGO_FEATURE_")
                .map(|f| f.to_ascii_lowercase().replace('_', "-"))
        })
        .filter(|f| {
            // Exclude synthetic internal crate dependency groupings
            !matches!(f.as_str(), "rustls-stack" | "boring" | "default")
        })
        .collect();

    // If the server-tls umbrella feature is enabled, suppress its constituent sub-features
    if features.iter().any(|f| f == "server-tls") {
        features.retain(|f| !matches!(f.as_str(), "server-doh" | "server-dot" | "server-h3"));
    }

    features.sort();
    let features_str = if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    };

    println!("cargo:rustc-env=POLARDNS_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=POLARDNS_ENABLED_FEATURES={features_str}");
}

fn emit_git_rerun_hints() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=build.rs");

    let Some(git_dir) = git_output(["rev-parse", "--git-dir"]).map(PathBuf::from) else {
        return;
    };

    let head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());
    println!("cargo:rerun-if-changed={}", git_dir.join("index").display());
    println!(
        "cargo:rerun-if-changed={}",
        git_dir.join("packed-refs").display()
    );

    if let Ok(head) = fs::read_to_string(&head_path)
        && let Some(ref_name) = head.strip_prefix("ref: ")
    {
        println!(
            "cargo:rerun-if-changed={}",
            git_dir.join(ref_name.trim()).display()
        );
    }
}

fn git_output<const N: usize>(args: [&str; N]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn git_worktree_is_dirty() -> bool {
    !git_status_is_success(["diff", "--quiet", "--ignore-submodules", "--"])
        || !git_status_is_success(["diff", "--cached", "--quiet", "--ignore-submodules", "--"])
}

fn git_status_is_success<const N: usize>(args: [&str; N]) -> bool {
    Command::new("git")
        .args(args)
        .status()
        .is_ok_and(|status| status.success())
}
