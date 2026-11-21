//! Operator-only bridge to the independently installed systemd helper.
//! This module takes no input from advisory discovery and performs no I/O
//! against the candidate paths itself, particularly not with administrator UID.

const USAGE: &str = "usage: boreas update verify MANIFEST ARTIFACT ED25519_SIG MLDSA65_SIG\n       boreas update apply --confirm-manifest-sha256 SHA256 MANIFEST ARTIFACT ED25519_SIG MLDSA65_SIG\n       Offline Linux/systemd only; supply absolute local paths.";

type Outcome = (u8, String, String);

fn absolute_inputs(args: &[String]) -> bool {
    args.len() == 4 && args.iter().all(|s| s.starts_with('/'))
}

fn valid_args(args: &[String]) -> bool {
    let Some((mode, rest)) = args.split_first() else {
        return false;
    };
    match (mode.as_str(), rest) {
        ("verify", files) => absolute_inputs(files),
        ("apply", [flag, hash, files @ ..]) => {
            flag == "--confirm-manifest-sha256"
                && hash.len() == 64
                && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                && absolute_inputs(files)
        }
        _ => false,
    }
}

pub(super) fn run(args: &[String]) -> Outcome {
    if args.len() == 1 && args[0] == "--help" {
        return (0, USAGE.into(), String::new());
    }
    if !valid_args(args) {
        return (2, String::new(), USAGE.into());
    }
    run_installed(args)
}

fn failed(message: impl Into<String>) -> Outcome {
    (1, String::new(), message.into())
}

#[cfg(not(target_os = "linux"))]
fn run_installed(_args: &[String]) -> Outcome {
    failed("Offline updates require the verified Linux/systemd deployment.")
}

#[cfg(target_os = "linux")]
fn run_installed(args: &[String]) -> Outcome {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::{Command, Stdio};

    // SAFETY: geteuid takes no arguments and does not modify memory.
    if unsafe { libc::geteuid() } != 0 {
        return failed("Offline updates require administrator credentials. Use sudo with the independently installed /usr/local/libexec/boreas/stage-verified-release (see boreas update --help). No elevation was attempted.");
    }
    let helper = Path::new("/usr/local/libexec/boreas/stage-verified-release");
    for path in helper.ancestors() {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return failed("The independently installed verified-release helper is missing.");
        };
        let correct_type = if path == helper {
            meta.is_file() && meta.mode() & 0o111 != 0
        } else {
            meta.is_dir()
        };
        if !correct_type || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return failed("The verified-release helper or its ancestry is not trusted.");
        }
    }
    match Command::new(helper)
        .args(args)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .status()
    {
        Ok(status) => (u8::from(!status.success()), String::new(), String::new()),
        Err(err) => failed(format!("Cannot start the verified-release helper: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_apply_requires_full_approval_and_four_local_files() {
        let files = ["/spool/manifest", "/spool/boreas", "/spool/ed", "/spool/pq"].map(String::from);
        let mut verify = vec![String::from("verify")];
        verify.extend(files.iter().cloned());
        assert!(valid_args(&verify));
        let mut args = vec![
            String::from("apply"),
            String::from("--confirm-manifest-sha256"),
            "a".repeat(64),
        ];
        args.extend(files.iter().cloned());
        assert!(valid_args(&args));
        args[3] = "https://example.invalid/release.json".into();
        assert_eq!(run(&args).0, 2);
        args[3] = files[0].clone();
        args[2] = "A".repeat(64);
        assert_eq!(run(&args).0, 2);
        let mut unapproved = vec![String::from("apply")];
        unapproved.extend(files);
        assert_eq!(run(&unapproved).0, 2);
        assert_eq!(run(&["--channel=pre".into()]).0, 2);
    }
}
