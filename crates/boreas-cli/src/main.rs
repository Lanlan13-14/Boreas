use std::env;
use std::process::ExitCode;

const IMPLEMENTATION_SCOPE: &str = "Phase 0 policy/parser foundation only";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (code, stdout, stderr) = run(&args);
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }
    ExitCode::from(code)
}

fn run(args: &[String]) -> (u8, String, String) {
    match args.first().map(String::as_str) {
        None | Some("doctor") | Some("self-check") if args.len() <= 1 => (0, doctor_json(), String::new()),
        None | Some("doctor") | Some("self-check") => (2, String::new(), "error: unexpected argument; run `boreas help`".into()),
        Some("help") | Some("--help") | Some("-h") if args.len() == 1 => (
            0,
            "boreas — minimal Phase 0 policy/parser foundation\n\nUSAGE:\n  boreas [doctor|self-check|help]\n\nNo daemon, TLS backend, or networking is implemented.".into(),
            String::new(),
        ),
        Some(command) => (2, String::new(), format!("error: unknown or unavailable command `{command}`; no daemon was started")),
    }
}

fn doctor_json() -> String {
    format!(
        "{{\"status\":\"foundation_only\",\"phase\":\"Phase 0\",\"scope\":\"{IMPLEMENTATION_SCOPE}\",\"daemon\":false,\"tls_backend\":false,\"networking\":false,\"phase0_complete\":false}}"
    )
}

#[cfg(test)]
mod tests {
    use super::run;

    fn args(values: &[&str]) -> Vec<String> { values.iter().map(|s| (*s).into()).collect() }

    #[test]
    fn doctor_command_reports_explicit_limitations() {
        let (code, stdout, stderr) = run(&args(&["doctor"]));
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"daemon\":false"));
        assert!(stdout.contains("\"tls_backend\":false"));
        assert!(stdout.contains("\"phase0_complete\":false"));
    }

    #[test]
    fn default_and_self_check_are_doctor() {
        assert_eq!(run(&[]).0, 0);
        assert_eq!(run(&args(&["self-check"])).0, 0);
    }

    #[test]
    fn daemon_and_unknown_commands_fail_without_starting() {
        for command in ["daemon", "made-up"] {
            let (code, stdout, stderr) = run(&args(&[command]));
            assert_eq!(code, 2);
            assert!(stdout.is_empty());
            assert!(stderr.contains("no daemon was started"));
        }
    }

    #[test]
    fn rejects_extra_arguments() {
        let (code, _, stderr) = run(&args(&["doctor", "unexpected"]));
        assert_eq!(code, 2);
        assert!(stderr.contains("unexpected argument"));
    }
}
