//! Pure-Rust OCI / Docker image & `.tar` layer scanner with "Ghost Layer" detection.
//! Inspects exported container tarballs (`docker save -o image.tar <img_ref>`) or live local images,
//! recursively walking nested `layer.tar` archives, image config `Env`/`history` metadata, and
//! OCI whiteout markers (`.wh.<file>`) to flag secrets that were deleted in later layers but remain
//! permanently extractable from intermediate layers.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::error::SentrisError;
use crate::model::{Finding, ScanReport, ScanStats};
use crate::scanner::Scanner;

const TAR_BLOCK: usize = 512;
const MAX_LAYER_FILE_BYTES: usize = 10 * 1024 * 1024;

struct LayerFinding {
    layer_idx: usize,
    inner_path: String,
    finding: Finding,
}

/// Parses an octal (or base-256) size field from a 512-byte POSIX tar header.
fn parse_tar_size(field: &[u8]) -> Option<usize> {
    if field.first().copied() == Some(0x80) {
        let mut val: usize = 0;
        for &b in &field[1..] {
            val = val.checked_mul(256)?.checked_add(b as usize)?;
        }
        return Some(val);
    }
    let text = std::str::from_utf8(field).ok()?;
    let trimmed = text.trim_matches(|c: char| c == '\0' || c.is_ascii_whitespace());
    if trimmed.is_empty() {
        return Some(0);
    }
    usize::from_str_radix(trimmed, 8).ok()
}

fn cstr_bytes(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("").trim()
}

/// Heuristic check for whether a byte slice is itself a nested POSIX/ustar tar archive.
fn looks_like_tar_archive(bytes: &[u8]) -> bool {
    if bytes.len() < TAR_BLOCK {
        return false;
    }
    let header = &bytes[..TAR_BLOCK];
    if header.iter().all(|&b| b == 0) {
        return false;
    }
    if &header[257..262] == b"ustar" {
        return true;
    }
    let name = cstr_bytes(&header[0..100]);
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        && parse_tar_size(&header[124..136]).is_some()
}

fn normalize_tar_path(raw: &str) -> String {
    raw.trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

struct ContainerScanState {
    files_scanned: usize,
    files_ignored: usize,
    bytes_scanned: u64,
    layer_counter: usize,
    layer_findings: Vec<LayerFinding>,
    /// Tracks `(layer_idx, whiteout_target_path)` for OCI `.wh.<file>` deletions.
    whiteouts: Vec<(usize, String)>,
    /// Tracks the latest layer index in which `inner_path` was written and the fingerprints present in that write.
    latest_file_state: HashMap<String, (usize, HashSet<String>)>,
}

impl Scanner {
    /// Scans a Docker / OCI image `.tar` archive or invokes `docker save <image>` when given an image reference.
    pub fn scan_docker(&self, target: &str) -> Result<ScanReport, SentrisError> {
        let start = Instant::now();
        let stripped = target.strip_prefix("docker://").unwrap_or(target);
        let path = Path::new(stripped);

        let tar_bytes = if path.exists() && path.is_file() {
            fs::read(path)?
        } else {
            export_docker_image_tar(stripped)?
        };

        let mut report = self.scan_docker_tar_bytes(&tar_bytes, stripped)?;
        report.stats.duration_ms = start.elapsed().as_millis();
        Ok(report)
    }

    /// Scans raw bytes of a Docker / OCI `.tar` archive, including nested `layer.tar` streams and Ghost Layer analysis.
    pub fn scan_docker_tar_bytes(
        &self,
        tar_bytes: &[u8],
        label: &str,
    ) -> Result<ScanReport, SentrisError> {
        let mut state = ContainerScanState {
            files_scanned: 0,
            files_ignored: 0,
            bytes_scanned: 0,
            layer_counter: 0,
            layer_findings: Vec::new(),
            whiteouts: Vec::new(),
            latest_file_state: HashMap::new(),
        };

        self.walk_tar_stream(tar_bytes, label, 0, &mut state);

        let mut findings = Vec::with_capacity(state.layer_findings.len());
        for mut lf in state.layer_findings {
            let deleted_by_whiteout = state.whiteouts.iter().any(|(wh_layer, wh_target)| {
                *wh_layer > lf.layer_idx
                    && (lf.inner_path == *wh_target
                        || (wh_target.ends_with('/') && lf.inner_path.starts_with(wh_target)))
            });
            let overwritten_without_secret = state
                .latest_file_state
                .get(&lf.inner_path)
                .is_some_and(|(last_layer, fps)| {
                    *last_layer > lf.layer_idx && !fps.contains(&lf.finding.fingerprint)
                });

            if (deleted_by_whiteout || overwritten_without_secret)
                && !lf.finding.description.contains("[GHOST LAYER")
            {
                lf.finding.description = format!(
                    "{} [GHOST LAYER: deleted in later layer but still extractable from image layer history]",
                    lf.finding.description
                );
            }
            findings.push(lf.finding);
        }

        let findings_count = findings.len();
        Ok(ScanReport {
            timestamp: format!("{}", crate::rotator::unix_now()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            stats: ScanStats {
                files_scanned: state.files_scanned,
                files_ignored: state.files_ignored,
                bytes_scanned: state.bytes_scanned,
                duration_ms: 0,
                findings_count,
            },
            findings,
            exposures: Default::default(),
        })
    }

    fn walk_tar_stream(
        &self,
        bytes: &[u8],
        archive_prefix: &str,
        current_layer: usize,
        state: &mut ContainerScanState,
    ) {
        let mut offset = 0usize;
        let mut pending_long_name: Option<String> = None;

        while offset + TAR_BLOCK <= bytes.len() {
            let header = &bytes[offset..offset + TAR_BLOCK];
            offset += TAR_BLOCK;

            if header.iter().all(|&b| b == 0) {
                continue;
            }
            let Some(size) = parse_tar_size(&header[124..136]) else {
                break;
            };
            let payload_end = offset.saturating_add(size).min(bytes.len());
            let payload = &bytes[offset..payload_end];
            let padded = (size.saturating_add(TAR_BLOCK - 1)) & !(TAR_BLOCK - 1);
            offset = offset.saturating_add(padded);

            let typeflag = header[156];
            if typeflag == b'L' {
                pending_long_name = Some(cstr_bytes(payload).to_string());
                continue;
            }

            let raw_name = if let Some(long_name) = pending_long_name.take() {
                long_name
            } else {
                let name = cstr_bytes(&header[0..100]);
                let prefix = if &header[257..262] == b"ustar" {
                    cstr_bytes(&header[345..500])
                } else {
                    ""
                };
                if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{prefix}/{name}")
                }
            };
            let entry_path = normalize_tar_path(&raw_name);
            if entry_path.is_empty() {
                continue;
            }

            // Detect OCI whiteout marker files (.wh.<filename> or .wh..wh..opq)
            let (parent_dir, base_name) = match entry_path.rsplit_once('/') {
                Some((dir, base)) => (format!("{dir}/"), base),
                None => (String::new(), entry_path.as_str()),
            };
            if base_name == ".wh..wh..opq" {
                state.whiteouts.push((current_layer, parent_dir));
                continue;
            } else if let Some(deleted_name) = base_name.strip_prefix(".wh.") {
                state
                    .whiteouts
                    .push((current_layer, format!("{parent_dir}{deleted_name}")));
                continue;
            }

            if !(typeflag == 0 || typeflag == b'0') {
                continue;
            }

            // Nested layer tarball (e.g. `<layer-id>/layer.tar` or `blobs/sha256/<hash>`)
            if (entry_path.ends_with(".tar") || entry_path.starts_with("blobs/sha256/"))
                && looks_like_tar_archive(payload)
            {
                state.layer_counter += 1;
                let next_layer = state.layer_counter;
                let nested_prefix = format!("{archive_prefix}!layer-{next_layer}");
                self.walk_tar_stream(payload, &nested_prefix, next_layer, state);
                continue;
            }

            if payload.len() > MAX_LAYER_FILE_BYTES || payload.contains(&0) {
                state.files_ignored += 1;
                continue;
            }

            let Ok(text) = std::str::from_utf8(payload) else {
                state.files_ignored += 1;
                continue;
            };

            state.files_scanned += 1;
            state.bytes_scanned += payload.len() as u64;

            let display_path = format!("{archive_prefix}:{entry_path}");
            let found = self.detector.scan_text(text, &display_path);
            let mut fps = HashSet::new();
            for f in found {
                fps.insert(f.fingerprint.clone());
                state.layer_findings.push(LayerFinding {
                    layer_idx: current_layer,
                    inner_path: entry_path.clone(),
                    finding: f,
                });
            }
            state
                .latest_file_state
                .insert(entry_path, (current_layer, fps));
        }
    }
}

fn export_docker_image_tar(image_ref: &str) -> Result<Vec<u8>, SentrisError> {
    if image_ref.starts_with('-') || image_ref.is_empty() {
        return Err(SentrisError::Scan(format!(
            "Invalid Docker image reference: '{image_ref}'"
        )));
    }
    let docker_bin = std::env::var_os("SENTRIS_DOCKER_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("docker"));

    let out = Command::new(&docker_bin)
        .args(["save", image_ref])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| {
            SentrisError::Scan(format!(
                "Failed to run '{} save {image_ref}' (ensure Docker is running or pass an exported .tar file): {e}",
                docker_bin.display()
            ))
        })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(SentrisError::Scan(format!(
            "'{} save {image_ref}' failed: {}",
            docker_bin.display(),
            stderr.trim()
        )));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid 512-byte ustar tar entry `(header + padded payload)`.
    fn build_tar_entry(path: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; TAR_BLOCK];
        let name_bytes = path.as_bytes();
        let copy_len = name_bytes.len().min(100);
        header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        header[100..107].copy_from_slice(b"0000644");
        let size_octal = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size_octal.as_bytes());
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        let checksum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        let chk_str = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(chk_str.as_bytes());

        let mut out = Vec::from(header);
        out.extend_from_slice(data);
        let rem = data.len() % TAR_BLOCK;
        if rem != 0 {
            out.resize(out.len() + (TAR_BLOCK - rem), 0);
        }
        out
    }

    fn finish_tar(mut entries: Vec<u8>) -> Vec<u8> {
        entries.resize(entries.len() + TAR_BLOCK * 2, 0);
        entries
    }

    #[test]
    fn detects_ghost_layer_secret_deleted_in_later_layer() {
        let leaked_env = concat!(
            "STRIPE_SECRET_KEY=\"",
            "sk_live_",
            "51Nq8xT2LmV7pRz0aBcDeFgHiJk9WsYuXo3Zt4\"\n"
        );
        // Layer 1 adds app/.env with a live Stripe key
        let layer1 = finish_tar(build_tar_entry("app/.env", leaked_env.as_bytes()));
        // Layer 2 deletes app/.env via OCI whiteout marker app/.wh..env
        let layer2 = finish_tar(build_tar_entry("app/.wh..env", b""));

        // Outer image.tar contains config.json, layer1/layer.tar, and layer2/layer.tar
        let config_json = br#"{"config":{"Env":["PATH=/usr/bin"]}}"#;
        let mut outer = Vec::new();
        outer.extend(build_tar_entry("config.json", config_json));
        outer.extend(build_tar_entry("layer1/layer.tar", &layer1));
        outer.extend(build_tar_entry("layer2/layer.tar", &layer2));
        let image_tar = finish_tar(outer);

        let scanner = Scanner::new().expect("scanner");
        let report = scanner
            .scan_docker_tar_bytes(&image_tar, "acme/billing:v1")
            .expect("scan docker tar");

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "stripe-secret-key");
        assert!(
            report.findings[0].description.contains("[GHOST LAYER"),
            "Expected Ghost Layer tag, got: {}",
            report.findings[0].description
        );
        assert!(report.findings[0]
            .file_path
            .contains("acme/billing:v1!layer-1:app/.env"));
    }
}
