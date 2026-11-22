//! A system curl adapter: fixed OS paths, caller-validated HTTPS URLs; no
//! shell, config, redirection, inherited proxy/credentials, or HTTP customization.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use super::json::MAX_BYTES;
use super::{Issue, Source};

#[cfg(unix)]
fn system_curl() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    // Never search PATH or invoke a writable binary/ancestor of a symlink
    // target. The OS administrator and OS trust store are the trust boundary.
    let paths = ["/usr/bin/curl", "/bin/curl"].map(std::path::Path::new);
    paths.iter().find_map(|path| {
        let target = path.canonicalize().ok()?;
        if !paths.contains(&target.as_path()) || !std::fs::metadata(&target).ok()?.is_file() {
            return None;
        }
        for component in path.ancestors().chain(target.ancestors()) {
            let meta = std::fs::metadata(component).ok()?;
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return None;
            }
        }
        Some(target)
    })
}

#[cfg(windows)]
fn system_curl() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, len: u32) -> u32;
    }

    let mut buffer = [0_u16; 260];
    // SAFETY: the buffer is writable for the supplied number of UTF-16 units.
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), 260) } as usize;
    if len == 0 || len >= buffer.len() {
        return None;
    }
    let path = PathBuf::from(OsString::from_wide(&buffer[..len])).join("curl.exe");
    (path.is_absolute() && path.is_file()).then_some(path)
}

#[cfg(not(any(unix, windows)))]
fn system_curl() -> Option<PathBuf> {
    None
}

fn stop(mut child: Child) {
    let _ = child.kill();
    // No blocking wait on the UI thread after the deadline. Reap even when
    // the OS does not deliver termination immediately.
    if !matches!(child.try_wait(), Ok(Some(_))) {
        let _ = thread::Builder::new().spawn(move || child.wait());
    }
}

pub(super) fn fetch(source: Source, deadline: Instant) -> Result<Vec<u8>, Issue> {
    fetch_https(source.url(), MAX_BYTES, "Accept: application/json", deadline)
}

pub(super) fn fetch_https(
    url: &str,
    max_bytes: usize,
    accept: &'static str,
    deadline: Instant,
) -> Result<Vec<u8>, Issue> {
    let exe = system_curl().ok_or(Issue::NoCurl)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.as_millis() == 0 {
        return Err(Issue::Timeout);
    }
    let mut command = Command::new(&exe);
    command
        .env_clear()
        .current_dir(exe.parent().ok_or(Issue::NoCurl)?)
        .args([
            "-q", // Must be the first curl argument: ignore .curlrc.
            "--silent",
            "--globoff",
            "--proto",
            "=https",
            "--tlsv1.2",
            // Older Schannel curl versions must fail before any network I/O:
            // they could otherwise offer a system client certificate.
            "--no-ssl-auto-client-cert",
            "--proxy",
            "",
            "--max-time",
            &format!("{}.{:03}", remaining.as_secs(), remaining.subsec_millis()),
            "--max-filesize",
            &max_bytes.to_string(),
            "--header",
            accept,
            "--user-agent",
            "boreas-release-check",
            "--write-out",
            "\n%{http_code}",
            "--",
            url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Use the OS-provided root, not an inherited SystemRoot override.
        if let Some(root) = exe.parent().and_then(std::path::Path::parent) {
            command.env("SystemRoot", root);
        }
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn().map_err(|error| {
        if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied) {
            Issue::NoCurl
        } else {
            Issue::Transport
        }
    })?;
    let Some(stdout) = child.stdout.take() else {
        stop(child);
        return Err(Issue::Transport);
    };
    let (sender, receiver) = sync_channel(1);
    if thread::Builder::new().spawn(move || {
        // Permit the 4-byte status suffix and detect one overflow byte, even
        // with curl versions that cannot limit a chunked response themselves.
        let _ = sender.send(read_response(stdout, max_bytes));
    }).is_err() {
        stop(child);
        return Err(Issue::Transport);
    }
    let bytes = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(bytes)) if bytes.len() <= max_bytes + 4 => bytes,
        other => {
            stop(child);
            return Err(match other {
                Ok(Ok(_)) => Issue::TooLarge,
                Err(RecvTimeoutError::Timeout) => Issue::Timeout,
                _ => Issue::Transport,
            });
        }
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            stop(child);
            return Err(Issue::Timeout);
        }
        match child.try_wait() {
            Ok(Some(status)) => return response(status.code(), bytes),
            Ok(None) => thread::sleep(remaining.min(Duration::from_millis(5))),
            Err(_) => {
                stop(child);
                return Err(Issue::Transport);
            }
        }
    }
}

fn read_response(reader: impl Read, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take((max_bytes + 5) as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn response(exit: Option<i32>, mut bytes: Vec<u8>) -> Result<Vec<u8>, Issue> {
    match exit {
        Some(0) => (),
        Some(2 | 4) => return Err(Issue::NoCurl),
        Some(28) => return Err(Issue::Timeout),
        Some(5..=7) => return Err(Issue::Connect),
        Some(35 | 51 | 58..=60 | 77 | 82 | 83 | 90 | 91) => return Err(Issue::Tls),
        Some(63) => return Err(Issue::TooLarge),
        _ => return Err(Issue::Transport),
    }
    let split = bytes.len().checked_sub(4).ok_or(Issue::Transport)?;
    let suffix = &bytes[split..];
    if suffix[0] != b'\n' || !suffix[1..].iter().all(u8::is_ascii_digit) {
        return Err(Issue::Transport);
    }
    let code = suffix[1..].iter().fold(0_u16, |n, b| n * 10 + u16::from(*b - b'0'));
    if code != 200 {
        return Err(Issue::Http(code));
    }
    bytes.truncate(split);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_keeps_binary_bodies_and_detects_overflow() {
        let exact = b"\x00\xff\n200\n200";
        let bytes = read_response(&exact[..], 6).unwrap();
        assert_eq!(response(Some(0), bytes), Ok(b"\x00\xff\n200".to_vec()));
        let overflow = std::io::repeat(0);
        assert_eq!(read_response(overflow, 64).unwrap().len(), 64 + 5);
    }

    #[test]
    fn status_suffix_does_not_accept_redirects_or_errors() {
        assert_eq!(response(Some(0), b"[]\n200".to_vec()), Ok(b"[]".to_vec()));
        for status in [301, 403, 404, 429] {
            assert_eq!(response(Some(0), format!("[]\n{status}").into_bytes()), Err(Issue::Http(status)));
        }
        assert_eq!(response(Some(60), vec![]), Err(Issue::Tls));
        assert_eq!(response(Some(28), vec![]), Err(Issue::Timeout));
        assert_eq!(response(Some(63), vec![]), Err(Issue::TooLarge));
        assert_eq!(response(Some(0), b"[]200".to_vec()), Err(Issue::Transport));
    }
}
