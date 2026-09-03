//! Local-only verification for one deliberately narrow Sigstore format.
//!
//! The supported input is a regular file named with a .tar.gz suffix and a
//! Sigstore Bundle v0.3 containing one SHA-256 MessageSignature. The bundle
//! and a serialized trusted root must be placed directly in the evidence
//! directory. No archive extraction, TUF update, HTTP client, or remote
//! lookup is part of this crate.

use serde::Serialize;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use sigstore_trust_root::TrustedRoot;
use sigstore_verify::VerificationPolicy;
use sigstore_verify::types::bundle::VerificationMaterialContent;
use sigstore_verify::types::{Bundle, HashAlgorithm, Sha256Hash, SignatureContent};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub const SCHEMA_VERSION: &str = "airgap-verify/v1";
pub const SUPPORTED_BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
pub const BUNDLE_FILE_NAME: &str = "bundle.sigstore.json";
pub const TRUSTED_ROOT_FILE_NAME: &str = "trusted-root.json";
pub const MAX_EVIDENCE_ENTRIES: usize = 128;
pub const MAX_EVIDENCE_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_EVIDENCE_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub schema_version: &'static str,
    pub artifact: ArtifactReport,
    pub signature: ClaimReport,
    pub certificate_chain: ClaimReport,
    pub timestamp: ClaimReport,
    pub transparency: ClaimReport,
    pub trust_roots_used: Vec<String>,
    pub network_access_attempted: bool,
    pub missing_or_unverifiable_claims: Vec<String>,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactReport {
    pub name: String,
    pub size_bytes: Option<u64>,
    pub digest_algorithm: &'static str,
    pub digest: Option<String>,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimReport {
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectReport {
    pub schema_version: &'static str,
    pub files: Vec<EvidenceFileReport>,
    pub bundle: ClaimReport,
    pub trusted_root: ClaimReport,
    pub network_access_attempted: bool,
    pub missing_or_unverifiable_claims: Vec<String>,
    pub verdict: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceFileReport {
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug)]
struct EvidenceLoad {
    files: Vec<EvidenceFileReport>,
    contents: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Default)]
struct BundleFacts {
    expected_digest: Option<Sha256Hash>,
    signature_present: bool,
    certificate_present: bool,
    transparency_present: bool,
    timestamp_present: bool,
    issues: Vec<String>,
}

/// Verify the supported artifact and evidence directory.
///
/// The returned report is also produced for expected verification failures.
/// A pass verdict means the artifact digest, detached signature, Fulcio
/// certificate chain, signed time, and Rekor inclusion evidence all verified
/// against the supplied local trusted root.
pub fn verify_artifact(artifact_path: &Path, evidence_path: &Path) -> VerificationReport {
    let mut report = new_verification_report(artifact_name(artifact_path));

    let artifact = match hash_artifact(artifact_path) {
        Ok(value) => {
            report.artifact.size_bytes = Some(value.size_bytes);
            report.artifact.digest = Some(value.digest.to_hex());
            report.artifact.status = "digest-computed".to_string();
            value
        }
        Err(error) => {
            report.artifact.status = "unavailable".to_string();
            add_claim(&mut report.missing_or_unverifiable_claims, error);
            return finish_verification_report(report);
        }
    };

    let evidence = match load_evidence(evidence_path) {
        Ok(value) => value,
        Err(error) => {
            add_claim(
                &mut report.missing_or_unverifiable_claims,
                format!("evidence: {error}"),
            );
            return finish_verification_report(report);
        }
    };

    let bundle_bytes = match evidence.contents.get(BUNDLE_FILE_NAME) {
        Some(value) => value,
        None => {
            add_claim(
                &mut report.missing_or_unverifiable_claims,
                format!("missing {BUNDLE_FILE_NAME}"),
            );
            return finish_verification_report(report);
        }
    };
    let root_bytes = match evidence.contents.get(TRUSTED_ROOT_FILE_NAME) {
        Some(value) => value,
        None => {
            add_claim(
                &mut report.missing_or_unverifiable_claims,
                format!("missing {TRUSTED_ROOT_FILE_NAME}"),
            );
            return finish_verification_report(report);
        }
    };

    let bundle_json = match json_text(bundle_bytes, BUNDLE_FILE_NAME) {
        Ok(value) => value,
        Err(error) => {
            mark_unverifiable(&mut report, "bundle JSON", &error);
            return finish_verification_report(report);
        }
    };
    if let Err(error) = reject_duplicate_json_keys(bundle_json) {
        mark_unverifiable(&mut report, "bundle JSON", &error);
        return finish_verification_report(report);
    }
    let bundle = match Bundle::from_json(bundle_json) {
        Ok(value) => value,
        Err(error) => {
            mark_unverifiable(&mut report, "bundle JSON", &error.to_string());
            return finish_verification_report(report);
        }
    };

    let facts = bundle_facts(&bundle);
    report.signature.status = if facts.signature_present {
        "present".to_string()
    } else {
        "missing".to_string()
    };
    report.certificate_chain.status = if facts.certificate_present {
        "present".to_string()
    } else {
        "missing".to_string()
    };
    report.transparency.status = if facts.transparency_present {
        "present".to_string()
    } else {
        "missing".to_string()
    };
    report.timestamp.status = if facts.timestamp_present {
        "present".to_string()
    } else {
        "missing".to_string()
    };
    for issue in facts.issues {
        add_claim(&mut report.missing_or_unverifiable_claims, issue);
    }
    match facts.expected_digest {
        Some(expected) if expected == artifact.digest => {}
        Some(_) => {
            report.signature = claim(
                "unverifiable",
                "bundle SHA-256 digest does not match the artifact",
            );
            add_claim(
                &mut report.missing_or_unverifiable_claims,
                "signature artifact binding".to_string(),
            );
            return finish_verification_report(report);
        }
        None => return finish_verification_report(report),
    }
    if !report.missing_or_unverifiable_claims.is_empty() {
        return finish_verification_report(report);
    }

    let root_json = match json_text(root_bytes, TRUSTED_ROOT_FILE_NAME) {
        Ok(value) => value,
        Err(error) => {
            mark_unverifiable(&mut report, "trusted root", &error);
            return finish_verification_report(report);
        }
    };
    if let Err(error) = reject_duplicate_json_keys(root_json) {
        mark_unverifiable(&mut report, "trusted root", &error);
        return finish_verification_report(report);
    }
    let root = match TrustedRoot::from_json(root_json) {
        Ok(value) => value,
        Err(error) => {
            mark_unverifiable(&mut report, "trusted root", &error.to_string());
            return finish_verification_report(report);
        }
    };
    report.trust_roots_used = vec![TRUSTED_ROOT_FILE_NAME.to_string()];
    if let Err(error) = validate_trusted_root(&root) {
        mark_unverifiable(&mut report, "trusted root", &error);
        return finish_verification_report(report);
    }

    let policy = VerificationPolicy::default();
    match sigstore_verify::verify(artifact.digest, &bundle, &policy, &root) {
        Ok(result) => {
            report.signature = claim("verified", "detached SHA-256 signature verified");
            report.certificate_chain = claim("verified", "certificate chain and SCT verified");
            report.transparency = claim("verified", "Rekor inclusion evidence verified");
            if result.integrated_time.is_some() {
                report.timestamp = claim("verified", "signed entry timestamp verified");
                report.verdict = "pass".to_string();
            } else {
                report.timestamp = claim(
                    "unverifiable",
                    "verification returned no verified integrated time",
                );
                add_claim(
                    &mut report.missing_or_unverifiable_claims,
                    "verified timestamp".to_string(),
                );
            }
        }
        Err(error) => {
            mark_unverifiable(
                &mut report,
                "cryptographic verification",
                &error.to_string(),
            );
        }
    }

    finish_verification_report(report)
}

/// Inspect the evidence directory without verifying an artifact.
pub fn inspect_evidence(evidence_path: &Path) -> InspectReport {
    let mut report = InspectReport {
        schema_version: SCHEMA_VERSION,
        files: Vec::new(),
        bundle: claim("missing", "not inspected"),
        trusted_root: claim("missing", "not inspected"),
        network_access_attempted: false,
        missing_or_unverifiable_claims: Vec::new(),
        verdict: "fail".to_string(),
    };

    let evidence = match load_evidence(evidence_path) {
        Ok(value) => value,
        Err(error) => {
            add_claim(
                &mut report.missing_or_unverifiable_claims,
                format!("evidence: {error}"),
            );
            return finish_inspect_report(report);
        }
    };
    report.files = evidence.files;

    let bundle_bytes = match evidence.contents.get(BUNDLE_FILE_NAME) {
        Some(value) => value,
        None => {
            add_claim(
                &mut report.missing_or_unverifiable_claims,
                format!("missing {BUNDLE_FILE_NAME}"),
            );
            return finish_inspect_report(report);
        }
    };
    let root_bytes = match evidence.contents.get(TRUSTED_ROOT_FILE_NAME) {
        Some(value) => value,
        None => {
            add_claim(
                &mut report.missing_or_unverifiable_claims,
                format!("missing {TRUSTED_ROOT_FILE_NAME}"),
            );
            return finish_inspect_report(report);
        }
    };

    let bundle_json = match json_text(bundle_bytes, BUNDLE_FILE_NAME) {
        Ok(value) => value,
        Err(error) => {
            report.bundle = claim("unverifiable", &error);
            add_claim(&mut report.missing_or_unverifiable_claims, error);
            return finish_inspect_report(report);
        }
    };
    if let Err(error) = reject_duplicate_json_keys(bundle_json) {
        report.bundle = claim("unverifiable", &error);
        add_claim(&mut report.missing_or_unverifiable_claims, error);
        return finish_inspect_report(report);
    }
    let bundle = match Bundle::from_json(bundle_json) {
        Ok(value) => value,
        Err(error) => {
            let detail = error.to_string();
            report.bundle = claim("unverifiable", &detail);
            add_claim(&mut report.missing_or_unverifiable_claims, detail);
            return finish_inspect_report(report);
        }
    };
    let facts = bundle_facts(&bundle);
    if facts.issues.is_empty() {
        report.bundle = claim(
            "parseable",
            "supported v0.3 detached message-signature structure is present",
        );
    } else {
        report.bundle = claim("unverifiable", "bundle claims are incomplete");
        for issue in facts.issues {
            add_claim(&mut report.missing_or_unverifiable_claims, issue);
        }
    }

    let root_json = match json_text(root_bytes, TRUSTED_ROOT_FILE_NAME) {
        Ok(value) => value,
        Err(error) => {
            report.trusted_root = claim("unverifiable", &error);
            add_claim(&mut report.missing_or_unverifiable_claims, error);
            return finish_inspect_report(report);
        }
    };
    if let Err(error) = reject_duplicate_json_keys(root_json) {
        report.trusted_root = claim("unverifiable", &error);
        add_claim(&mut report.missing_or_unverifiable_claims, error);
        return finish_inspect_report(report);
    }
    match TrustedRoot::from_json(root_json) {
        Ok(root) => match validate_trusted_root(&root) {
            Ok(()) => {
                report.trusted_root = claim(
                    "parseable",
                    "local trusted root has Rekor, Fulcio, and CT material",
                );
            }
            Err(error) => {
                report.trusted_root = claim("unverifiable", &error);
                add_claim(&mut report.missing_or_unverifiable_claims, error);
            }
        },
        Err(error) => {
            let detail = error.to_string();
            report.trusted_root = claim("unverifiable", &detail);
            add_claim(&mut report.missing_or_unverifiable_claims, detail);
        }
    }

    finish_inspect_report(report)
}

fn new_verification_report(name: String) -> VerificationReport {
    VerificationReport {
        schema_version: SCHEMA_VERSION,
        artifact: ArtifactReport {
            name,
            size_bytes: None,
            digest_algorithm: "SHA-256",
            digest: None,
            status: "unavailable".to_string(),
        },
        signature: claim("missing", "not verified"),
        certificate_chain: claim("missing", "not verified"),
        timestamp: claim("missing", "not verified"),
        transparency: claim("missing", "not verified"),
        trust_roots_used: Vec::new(),
        network_access_attempted: false,
        missing_or_unverifiable_claims: Vec::new(),
        verdict: "fail".to_string(),
    }
}

fn claim(status: &str, detail: &str) -> ClaimReport {
    ClaimReport {
        status: status.to_string(),
        detail: detail.to_string(),
    }
}

fn mark_unverifiable(report: &mut VerificationReport, subject: &str, detail: &str) {
    let message = format!("{subject}: {detail}");
    if report.signature.status == "present" {
        report.signature = claim("unverifiable", &message);
    }
    if report.certificate_chain.status == "present" {
        report.certificate_chain = claim("unverifiable", &message);
    }
    if report.timestamp.status == "present" {
        report.timestamp = claim("unverifiable", &message);
    }
    if report.transparency.status == "present" {
        report.transparency = claim("unverifiable", &message);
    }
    add_claim(&mut report.missing_or_unverifiable_claims, message);
}

fn finish_verification_report(mut report: VerificationReport) -> VerificationReport {
    sort_claims(&mut report.missing_or_unverifiable_claims);
    if !report.missing_or_unverifiable_claims.is_empty() {
        report.verdict = "fail".to_string();
    }
    report
}

fn finish_inspect_report(mut report: InspectReport) -> InspectReport {
    sort_claims(&mut report.missing_or_unverifiable_claims);
    if report.missing_or_unverifiable_claims.is_empty()
        && report.bundle.status == "parseable"
        && report.trusted_root.status == "parseable"
    {
        report.verdict = "pass".to_string();
    }
    report
}

fn sort_claims(claims: &mut Vec<String>) {
    claims.sort();
    claims.dedup();
}

fn add_claim(claims: &mut Vec<String>, value: String) {
    claims.push(value);
}

fn artifact_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "<non-utf8-artifact-name>".to_string())
}

struct ArtifactDigest {
    size_bytes: u64,
    digest: Sha256Hash,
}

fn hash_artifact(path: &Path) -> Result<ArtifactDigest, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("artifact could not be opened: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("artifact symlink is not allowed".to_string());
    }
    if !metadata.file_type().is_file() {
        return Err("artifact must be a regular file".to_string());
    }
    if !artifact_name(path).ends_with(".tar.gz") {
        return Err("supported artifact format is a regular .tar.gz file".to_string());
    }

    let mut file =
        File::open(path).map_err(|error| format!("artifact could not be opened: {error}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size_bytes = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("artifact could not be read: {error}"))?;
        if count == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(count as u64)
            .ok_or_else(|| "artifact size overflow".to_string())?;
        hasher.update(&buffer[..count]);
    }
    let digest_bytes = hasher.finalize().to_vec();
    let digest = Sha256Hash::try_from_slice(&digest_bytes)
        .map_err(|error| format!("artifact digest could not be formed: {error}"))?;
    Ok(ArtifactDigest { size_bytes, digest })
}

fn load_evidence(path: &Path) -> Result<EvidenceLoad, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("evidence directory could not be opened: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("evidence directory symlink is not allowed".to_string());
    }
    if !metadata.file_type().is_dir() {
        return Err("evidence path must be a directory".to_string());
    }

    let mut directory_entries = Vec::new();
    for entry in fs::read_dir(path)
        .map_err(|error| format!("evidence directory could not be read: {error}"))?
    {
        let entry = entry.map_err(|error| format!("evidence entry could not be read: {error}"))?;
        directory_entries.push(entry);
    }
    if directory_entries.len() > MAX_EVIDENCE_ENTRIES {
        return Err(format!(
            "evidence entry count exceeds limit of {MAX_EVIDENCE_ENTRIES}"
        ));
    }
    directory_entries.sort_by_key(|entry| entry.file_name());

    let mut files = Vec::with_capacity(directory_entries.len());
    let mut contents = BTreeMap::new();
    let mut total_bytes = 0_u64;
    for entry in directory_entries {
        let name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| "evidence entry name is not valid UTF-8".to_string())?;
        if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
            return Err(format!("unsafe evidence entry name: {name:?}"));
        }
        let entry_type = entry
            .file_type()
            .map_err(|error| format!("evidence entry type could not be read: {error}"))?;
        if entry_type.is_symlink() {
            return Err(format!("evidence symlink is not allowed: {name}"));
        }
        if !entry_type.is_file() {
            return Err(format!("evidence entry is not a regular file: {name}"));
        }
        let metadata = entry
            .metadata()
            .map_err(|error| format!("evidence metadata could not be read: {error}"))?;
        if metadata.len() > MAX_EVIDENCE_FILE_BYTES {
            return Err(format!(
                "evidence file {name} exceeds limit of {MAX_EVIDENCE_FILE_BYTES} bytes"
            ));
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| "evidence size overflow".to_string())?;
        if total_bytes > MAX_EVIDENCE_TOTAL_BYTES {
            return Err(format!(
                "evidence total size exceeds limit of {MAX_EVIDENCE_TOTAL_BYTES} bytes"
            ));
        }
        let bytes = read_limited_file(&entry.path())?;
        let digest = Sha256::digest(&bytes);
        files.push(EvidenceFileReport {
            name: name.clone(),
            size_bytes: bytes.len() as u64,
            sha256: hex::encode(digest),
        });
        contents.insert(name, bytes);
    }
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(EvidenceLoad { files, contents })
}

fn read_limited_file(path: &Path) -> Result<Vec<u8>, String> {
    let file =
        File::open(path).map_err(|error| format!("evidence file could not be read: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_EVIDENCE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("evidence file could not be read: {error}"))?;
    if bytes.len() as u64 > MAX_EVIDENCE_FILE_BYTES {
        return Err(format!(
            "evidence file exceeds limit of {MAX_EVIDENCE_FILE_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

fn json_text<'a>(bytes: &'a [u8], name: &str) -> Result<&'a str, String> {
    std::str::from_utf8(bytes).map_err(|error| format!("{name} is not UTF-8: {error}"))
}

fn bundle_facts(bundle: &Bundle) -> BundleFacts {
    let mut facts = BundleFacts::default();
    if bundle.media_type != SUPPORTED_BUNDLE_MEDIA_TYPE {
        facts.issues.push(format!(
            "bundle media type must be {SUPPORTED_BUNDLE_MEDIA_TYPE}"
        ));
    }

    match &bundle.content {
        SignatureContent::MessageSignature(message) => {
            facts.signature_present = true;
            match &message.message_digest {
                Some(digest) if digest.algorithm == HashAlgorithm::Sha2256 => {
                    match Sha256Hash::try_from_slice(digest.digest.as_bytes()) {
                        Ok(value) => facts.expected_digest = Some(value),
                        Err(error) => facts
                            .issues
                            .push(format!("message digest is not a SHA-256 value: {error}")),
                    }
                }
                Some(digest) => facts.issues.push(format!(
                    "message digest algorithm must be SHA2_256, got {}",
                    digest.algorithm
                )),
                None => facts
                    .issues
                    .push("message signature is missing its artifact digest".to_string()),
            }
        }
        SignatureContent::DsseEnvelope(_) => facts.issues.push(
            "supported artifact format requires a detached MessageSignature, not DSSE".to_string(),
        ),
    }

    match &bundle.verification_material.content {
        VerificationMaterialContent::Certificate(certificate)
            if !certificate.raw_bytes.as_bytes().is_empty() =>
        {
            facts.certificate_present = true;
        }
        VerificationMaterialContent::Certificate(_) => {
            facts.issues.push("bundle certificate is empty".to_string())
        }
        VerificationMaterialContent::X509CertificateChain { .. } => facts
            .issues
            .push("supported v0.3 format requires one certificate field".to_string()),
        VerificationMaterialContent::PublicKey { .. } => facts
            .issues
            .push("supported format requires a certificate, not a public key".to_string()),
    }

    match bundle.verification_material.tlog_entries.as_slice() {
        [] => facts
            .issues
            .push("missing transparency-log entry".to_string()),
        [entry] => {
            if entry.inclusion_proof.is_some() {
                facts.transparency_present = true;
            } else {
                facts
                    .issues
                    .push("missing transparency inclusion proof".to_string());
            }
            if entry.inclusion_promise.is_some() && entry.integrated_time > 0 {
                facts.timestamp_present = true;
            } else {
                facts
                    .issues
                    .push("missing signed timestamp evidence".to_string());
            }
        }
        entries => facts.issues.push(format!(
            "duplicate transparency-log claims: expected 1 entry, found {}",
            entries.len()
        )),
    }

    facts
}

fn validate_trusted_root(root: &TrustedRoot) -> Result<(), String> {
    if root.tlogs.is_empty() {
        return Err("trusted root has no Rekor transparency-log keys".to_string());
    }
    if root.certificate_authorities.is_empty() {
        return Err("trusted root has no Fulcio certificate authorities".to_string());
    }
    if root.ctlogs.is_empty() {
        return Err("trusted root has no certificate-transparency log keys".to_string());
    }
    Ok(())
}

struct DuplicateKeyCheck;

impl<'de> DeserializeSeed<'de> for DuplicateKeyCheck {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateKeyCheck {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = access.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object key: {key}"
                )));
            }
            access.next_value_seed(DuplicateKeyCheck)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while access.next_element_seed(DuplicateKeyCheck)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

fn reject_duplicate_json_keys(json: &str) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    deserializer
        .deserialize_any(DuplicateKeyCheck)
        .map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_key_checker_rejects_nested_duplicate() {
        let error = reject_duplicate_json_keys(r#"{"outer":{"claim":1,"claim":2}}"#)
            .expect_err("duplicate keys must fail closed");
        assert!(error.contains("duplicate JSON object key: claim"));
    }

    #[test]
    fn duplicate_key_checker_accepts_distinct_keys() {
        reject_duplicate_json_keys(r#"{"one":1,"two":[true,null]}"#)
            .expect("distinct keys should parse");
    }

    #[test]
    fn bundle_facts_rejects_missing_timestamp() {
        let json = include_str!("../tests/fixtures/bundle.sigstore.json");
        let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
        value["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionPromise");
        let bundle = Bundle::from_json(&serde_json::to_string(&value).unwrap()).unwrap();
        let facts = bundle_facts(&bundle);
        assert!(!facts.timestamp_present);
        assert!(
            facts
                .issues
                .iter()
                .any(|issue| issue.contains("signed timestamp"))
        );
    }
}
