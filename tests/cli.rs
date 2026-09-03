use serde_json::Value;
use sigstore_trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::{TempDir, tempdir};

const ARTIFACT_FIXTURE: &[u8] = include_bytes!("fixtures/artifact.tar.gz");
const BUNDLE_FIXTURE: &[u8] = include_bytes!("fixtures/bundle.sigstore.json");

struct Fixture {
    _directory: TempDir,
    artifact: PathBuf,
    evidence: PathBuf,
}

fn fixture() -> Fixture {
    let directory = tempdir().expect("temporary directory");
    let artifact = directory.path().join("artifact.tar.gz");
    let evidence = directory.path().join("evidence");
    fs::create_dir(&evidence).expect("evidence directory");
    fs::write(&artifact, ARTIFACT_FIXTURE).expect("artifact fixture");
    fs::write(evidence.join("bundle.sigstore.json"), BUNDLE_FIXTURE).expect("bundle fixture");
    fs::write(
        evidence.join("trusted-root.json"),
        SIGSTORE_PRODUCTION_TRUSTED_ROOT,
    )
    .expect("trusted root fixture");
    assert_eq!(
        fs::read(&artifact).expect("read artifact fixture"),
        ARTIFACT_FIXTURE
    );
    assert_eq!(
        fs::read(evidence.join("bundle.sigstore.json")).expect("read bundle fixture"),
        BUNDLE_FIXTURE
    );
    Fixture {
        _directory: directory,
        artifact,
        evidence,
    }
}

fn verify_output(artifact: &Path, evidence: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_airgap-verify"))
        .args(["verify"])
        .arg(artifact)
        .arg(evidence)
        .output()
        .expect("run airgap-verify verify")
}

fn inspect_output(evidence: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_airgap-verify"))
        .args(["inspect"])
        .arg(evidence)
        .output()
        .expect("run airgap-verify inspect")
}

fn parse_report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("JSON report on stdout")
}

fn has_claim(report: &Value, needle: &str) -> bool {
    report["missingOrUnverifiableClaims"]
        .as_array()
        .expect("claims array")
        .iter()
        .filter_map(Value::as_str)
        .any(|claim| claim.contains(needle))
}

#[test]
fn valid_signature_reports_a_complete_pass() {
    let fixture = fixture();
    let output = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(output.status.success(), "{:?}", output);
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "pass");
    assert_eq!(
        report["artifact"]["digest"],
        "e194b99df6639501325c5f44da79fe3a8efae6f239bd79443a19787e06fb1764"
    );
    assert_eq!(report["signature"]["status"], "verified");
    assert_eq!(report["certificateChain"]["status"], "verified");
    assert_eq!(report["timestamp"]["status"], "verified");
    assert_eq!(report["transparency"]["status"], "verified");
    assert_eq!(
        report["trustRootsUsed"],
        serde_json::json!(["trusted-root.json"])
    );
    assert_eq!(report["networkAccessAttempted"], false);
    assert_eq!(report["missingOrUnverifiableClaims"], serde_json::json!([]));
}

#[test]
fn inspect_reports_the_local_evidence_inventory() {
    let fixture = fixture();
    let output = inspect_output(&fixture.evidence);
    assert!(output.status.success(), "{:?}", output);
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "pass");
    assert_eq!(report["bundle"]["status"], "parseable");
    assert_eq!(report["trustedRoot"]["status"], "parseable");
    let names: Vec<&str> = report["files"]
        .as_array()
        .expect("files array")
        .iter()
        .map(|file| file["name"].as_str().expect("file name"))
        .collect();
    assert_eq!(names, vec!["bundle.sigstore.json", "trusted-root.json"]);
}

#[test]
fn wrong_artifact_cannot_pass() {
    let fixture = fixture();
    let wrong_artifact = fixture.artifact.with_file_name("wrong.tar.gz");
    fs::write(&wrong_artifact, b"wrong artifact").expect("wrong artifact");
    assert_eq!(
        fs::read(&wrong_artifact).expect("read wrong artifact"),
        b"wrong artifact"
    );
    let output = verify_output(&wrong_artifact, &fixture.evidence);
    assert!(!output.status.success());
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "fail");
    assert_eq!(report["signature"]["status"], "unverifiable");
    assert!(has_claim(&report, "signature artifact binding"));
}

#[test]
fn wrong_trust_root_cannot_pass() {
    let fixture = fixture();
    let root_path = fixture.evidence.join("trusted-root.json");
    let wrong_root = r#"{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=1.0","tlogs":[],"certificateAuthorities":[],"ctlogs":[],"timestampAuthorities":[]}"#;
    fs::write(&root_path, wrong_root).expect("wrong trusted root");
    assert_eq!(
        fs::read_to_string(&root_path).expect("read wrong trusted root"),
        wrong_root
    );
    let output = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(!output.status.success());
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "fail");
    assert!(has_claim(&report, "trusted root has no Rekor"));
}

#[test]
fn missing_evidence_is_reported_as_incomplete() {
    let fixture = fixture();
    fs::remove_file(fixture.evidence.join("bundle.sigstore.json")).expect("remove bundle");
    assert!(!fixture.evidence.join("bundle.sigstore.json").exists());
    let output = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(!output.status.success());
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "fail");
    assert!(has_claim(&report, "missing bundle.sigstore.json"));
}

#[test]
fn expired_or_malformed_time_evidence_cannot_pass() {
    let fixture = fixture();
    let bundle_path = fixture.evidence.join("bundle.sigstore.json");
    let bundle = fs::read_to_string(&bundle_path).expect("read bundle");
    let expired = bundle.replace(
        "\"integratedTime\":\"1764787003\"",
        "\"integratedTime\":\"1\"",
    );
    assert_ne!(bundle, expired);
    fs::write(&bundle_path, expired).expect("expired bundle");
    assert!(
        fs::read_to_string(&bundle_path)
            .expect("read expired bundle")
            .contains("\"integratedTime\":\"1\"")
    );
    let output = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(!output.status.success());
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "fail");
    assert!(
        !report["missingOrUnverifiableClaims"]
            .as_array()
            .expect("claims array")
            .is_empty()
    );
}

#[test]
fn malformed_bundle_is_unverifiable() {
    let fixture = fixture();
    let bundle_path = fixture.evidence.join("bundle.sigstore.json");
    fs::write(&bundle_path, b"{not-json").expect("malformed bundle");
    assert_eq!(
        fs::read(&bundle_path).expect("read malformed bundle"),
        b"{not-json"
    );
    let output = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(!output.status.success());
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "fail");
    assert!(has_claim(&report, "bundle JSON"));
}

#[test]
fn duplicate_json_claims_are_rejected() {
    let fixture = fixture();
    let bundle_path = fixture.evidence.join("bundle.sigstore.json");
    let bundle = fs::read_to_string(&bundle_path).expect("read bundle");
    let duplicate = bundle.replacen(
        "\"mediaType\":",
        "\"mediaType\":\"duplicate\",\"mediaType\":",
        1,
    );
    assert_ne!(bundle, duplicate);
    fs::write(&bundle_path, duplicate).expect("duplicate claim bundle");
    let output = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(!output.status.success());
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "fail");
    assert!(has_claim(&report, "duplicate JSON object key"));
}

#[cfg(unix)]
#[test]
fn symlink_path_traversal_in_evidence_is_rejected() {
    let fixture = fixture();
    let outside = fixture._directory.path().join("outside-bundle.json");
    fs::write(&outside, BUNDLE_FIXTURE).expect("outside bundle");
    let bundle_path = fixture.evidence.join("bundle.sigstore.json");
    fs::remove_file(&bundle_path).expect("remove bundle");
    std::os::unix::fs::symlink(&outside, &bundle_path).expect("bundle symlink");
    assert!(
        fs::symlink_metadata(&bundle_path)
            .expect("bundle link metadata")
            .file_type()
            .is_symlink()
    );
    let output = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(!output.status.success());
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "fail");
    assert!(has_claim(&report, "evidence symlink"));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn verification_passes_under_a_network_syscall_deny_filter() {
    let fixture = fixture();
    let mut command = Command::new(env!("CARGO_BIN_EXE_airgap-verify"));
    command
        .args(["verify"])
        .arg(&fixture.artifact)
        .arg(&fixture.evidence);
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(install_network_deny_filter);
    }
    let output = command.output().expect("run under network deny filter");
    assert!(output.status.success(), "{:?}", output);
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "pass");
    assert_eq!(report["networkAccessAttempted"], false);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn install_network_deny_filter() -> io::Result<()> {
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

    let mut filter = vec![
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 4,
        },
        libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 1,
            jf: 0,
            k: AUDIT_ARCH_X86_64,
        },
        libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
        libc::sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    for syscall in [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
    ] {
        filter.push(libc::sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        });
    }
    filter.push(libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    let no_new_privs_result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privs_result != 0 {
        return Err(io::Error::last_os_error());
    }
    let program = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_mut_ptr(),
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const libc::sock_fprog,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[test]
fn verdict_json_is_deterministic() {
    let fixture = fixture();
    let first = verify_output(&fixture.artifact, &fixture.evidence);
    let second = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn large_evidence_file_is_rejected_before_parsing() {
    let fixture = fixture();
    let bundle_path = fixture.evidence.join("bundle.sigstore.json");
    let file = File::create(&bundle_path).expect("large bundle");
    file.set_len(airgap_verify::MAX_EVIDENCE_FILE_BYTES + 1)
        .expect("set large bundle length");
    assert_eq!(
        fs::metadata(&bundle_path)
            .expect("large bundle metadata")
            .len(),
        airgap_verify::MAX_EVIDENCE_FILE_BYTES + 1
    );
    let output = verify_output(&fixture.artifact, &fixture.evidence);
    assert!(!output.status.success());
    let report = parse_report(&output);
    assert_eq!(report["verdict"], "fail");
    assert!(has_claim(&report, "exceeds limit"));
}

#[test]
fn version_command_is_available() {
    let output = Command::new(env!("CARGO_BIN_EXE_airgap-verify"))
        .arg("version")
        .output()
        .expect("run version");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "airgap-verify 0.1.0\n"
    );
}
