//! Public sandbox-spec checks that do not install a filter or spawn a child.
//!
//! `WorkerSpec` does not exist. `sandbox` exposes a classic-BPF builder and a
//! userspace interpreter; `install` exposes a pure first-install decision.
//! Neither type checks a worker write path against an allowed root. A path
//! that escapes the store is rejected by `UpgradeStore` in `lib.rs`, but that
//! API creates directories and is not a `WorkerSpec` validator, so it is not
//! used here.
//!
//! This file does not call `install_current` and does not create a user
//! namespace. It is not `G-SANDBOX`.

use boreas_supervisor::install::{
    Outcome, Verifier, claims_post_quantum_install, install_outcome, unit_example,
};
use boreas_supervisor::sandbox::{
    BPF_MAXINSNS, SandboxError, TargetArch, eval, install_current, native_target, program,
    seccomp_data,
};

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const EPERM: u32 = 1;

fn action(target: TargetArch, nr: u32, args: [u64; 6]) -> u32 {
    let prog = program(target);
    assert!(prog.len() <= BPF_MAXINSNS);
    eval(&prog, &seccomp_data(nr, target.audit_arch(), args)).unwrap()
}

#[test]
fn filter_accepts_only_af_unix_stream_cloexec_and_rejects_udp() {
    let target = native_target().unwrap_or(TargetArch::Aarch64);
    let socket_nr: u32 = match target {
        TargetArch::X86_64 => 41,
        TargetArch::Aarch64 => 198,
    };
    let af_unix = 1u64;
    let af_inet = 2u64;
    let stream_cloexec = 1u64 | 0o2_000_000;
    let dgram = 2u64;

    assert_eq!(
        action(target, socket_nr, [af_unix, stream_cloexec, 0, 0, 0, 0]),
        SECCOMP_RET_ALLOW
    );
    let udp = action(target, socket_nr, [af_inet, dgram, 0, 0, 0, 0]);
    assert_eq!(udp, SECCOMP_RET_ERRNO | EPERM);
    assert_ne!(udp, SECCOMP_RET_ALLOW);

    // A foreign audit architecture is killed rather than allowed.
    let foreign = match target {
        TargetArch::X86_64 => TargetArch::Aarch64,
        TargetArch::Aarch64 => TargetArch::X86_64,
    };
    let prog = program(target);
    let killed = eval(
        &prog,
        &seccomp_data(
            socket_nr,
            foreign.audit_arch(),
            [af_unix, stream_cloexec, 0, 0, 0, 0],
        ),
    )
    .unwrap();
    assert_eq!(killed, SECCOMP_RET_KILL_PROCESS);
}

#[test]
fn install_current_is_unsupported_or_a_real_sandbox_error_and_is_not_called_to_succeed() {
    // On non-Linux this is the entire public install result. On Linux we do
    // not call it: a successful install cannot be undone. `native_target`
    // only reports whether a filter *could* be built.
    if native_target().is_none() {
        let err = install_current().expect_err("no native filter");
        assert!(matches!(
            err,
            SandboxError::Unsupported | SandboxError::UnsupportedArch
        ));
    } else {
        assert!(matches!(
            native_target(),
            Some(TargetArch::X86_64 | TargetArch::Aarch64)
        ));
    }
}

#[test]
fn install_decision_refuses_a_spec_that_failed_its_recorded_checks() {
    let refused = install_outcome(Verifier::PreTrustedExternal, false, false, true);
    assert!(matches!(refused, Outcome::Refused(_)));
    assert!(!claims_post_quantum_install(refused));

    let accepted = install_outcome(Verifier::PreTrustedExternal, false, true, true);
    assert_eq!(accepted, Outcome::ReadyToExec);
    assert!(!claims_post_quantum_install(accepted));

    let example = unit_example();
    assert!(example.memory_max >= example.memory_high);
}
