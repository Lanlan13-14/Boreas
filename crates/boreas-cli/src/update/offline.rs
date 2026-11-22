//! Operator-only bridge to the independently installed systemd helper.
//! This module takes no input from advisory discovery and performs no I/O
//! against the candidate paths itself, particularly not with administrator UID.

use crate::i18n::Lang;

const USAGE: &str = "usage: boreas update verify MANIFEST ARTIFACT ED25519_SIG MLDSA65_SIG\n       boreas update apply --confirm-manifest-sha256 SHA256 MANIFEST ARTIFACT ED25519_SIG MLDSA65_SIG\n       boreas update apply --confirm-manifest-sha256 SHA256 --signed-feed HTTPS_BASE_URL\n       Linux/systemd; local inputs must be absolute. Online apply requires OpenSSL 3.5+ and uses the installed release root.";

type Outcome = (u8, String, String);
const CONFIRM: &str = "--confirm-manifest-sha256";

fn approved_sha256(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn online_args(args: &[String]) -> Option<(&str, &str)> {
    match args {
        [mode, flag, hash, feed_flag, base]
            if mode == "apply" && flag == CONFIRM && approved_sha256(hash) && feed_flag == "--signed-feed" =>
        {
            Some((hash, base))
        }
        _ => None,
    }
}

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
            flag == CONFIRM && approved_sha256(hash) && absolute_inputs(files)
        }
        _ => false,
    }
}

pub(super) fn run(args: &[String], lang: Lang) -> Outcome {
    if args.len() == 1 && args[0] == "--help" {
        return (0, USAGE.into(), String::new());
    }
    if let Some((hash, base)) = online_args(args) {
        #[cfg(all(target_os = "linux", feature = "openssl-inner-tls"))]
        return super::signed::apply_online(base, hash, lang);
        #[cfg(not(all(target_os = "linux", feature = "openssl-inner-tls")))]
        {
            let _ = (hash, base, lang);
            return failed("Online apply requires a Linux build with openssl-inner-tls (OpenSSL 3.5+).");
        }
    }
    if !valid_args(args) {
        return (2, String::new(), USAGE.into());
    }
    run_installed(args)
}

pub(super) fn failed(message: impl Into<String>) -> Outcome {
    (1, String::new(), message.into())
}

#[cfg(not(target_os = "linux"))]
fn run_installed(_args: &[String]) -> Outcome {
    failed("Offline updates require the verified Linux/systemd deployment.")
}

#[cfg(target_os = "linux")]
fn run_installed(args: &[String]) -> Outcome {
    match installed_helper() {
        Ok(helper) => invoke(helper, args),
        Err(message) => failed(message),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn installed_helper() -> Result<&'static std::path::Path, &'static str> {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    // SAFETY: these calls only query process credentials.
    if unsafe { libc::geteuid() != 0 || libc::getuid() != 0 } {
        return Err("Updates require administrator credentials. Use the independently installed trusted update tools (see boreas update --help). No elevation was attempted.");
    }
    let helper = Path::new("/usr/local/libexec/boreas/stage-verified-release");
    for path in helper.ancestors() {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return Err("The independently installed verified-release helper is missing.");
        };
        let correct_type = if path == helper {
            meta.is_file() && meta.mode() & 0o111 != 0
        } else {
            meta.is_dir()
        };
        if !correct_type || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err("The verified-release helper or its ancestry is not trusted.");
        }
    }
    Ok(helper)
}

#[cfg(target_os = "linux")]
pub(super) fn invoke(helper: &std::path::Path, args: &[String]) -> Outcome {
    use std::process::{Command, Stdio};

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
        assert_eq!(run(&args, Lang::En).0, 2);
        args[3] = files[0].clone();
        args[2] = "A".repeat(64);
        assert_eq!(run(&args, Lang::En).0, 2);
        let mut unapproved = vec![String::from("apply")];
        unapproved.extend(files);
        assert_eq!(run(&unapproved, Lang::En).0, 2);
        assert_eq!(run(&["--channel=pre".into()], Lang::En).0, 2);
    }

    #[test]
    fn online_apply_requires_explicit_feed_and_full_approval_without_overrides() {
        let base = "https://example.test/release";
        let mut args = ["apply", CONFIRM, &"a".repeat(64), "--signed-feed", base].map(String::from).to_vec();
        assert_eq!(online_args(&args), Some((args[2].as_str(), base)));
        assert!(!valid_args(&args));
        #[cfg(not(all(target_os = "linux", feature = "openssl-inner-tls")))]
        assert_eq!(run(&args, Lang::En).0, 1);
        assert_eq!(run(&args[..2], Lang::En).0, 2);
        args.extend(["--trust-dir".into(), "/operator-root".into()]);
        assert_eq!(run(&args, Lang::En).0, 2);
        args.truncate(5);
        args[2].pop();
        assert_eq!(run(&args, Lang::En).0, 2);
    }
}
