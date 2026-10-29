use crate::error::SentrisError;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Replaces `path` with `content` via temp file + fsync + rename so a crash never leaves a truncated source file.
/// Refuses symlinks (a patch must not write through a link to somewhere else) and keeps the original permissions.
pub fn write_atomic(path: &Path, content: &str) -> Result<(), SentrisError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(SentrisError::Scan(format!(
            "Refusing to modify symlink: {}",
            path.display()
        )));
    }
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut rnd = [0u8; 6];
    getrandom::getrandom(&mut rnd).map_err(|e| SentrisError::Scan(e.to_string()))?;
    let tmp = dir.join(format!(".{name}.sentris-{}", hex::encode(rnd)));

    let result = (|| -> Result<(), SentrisError> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(content.as_bytes())?;
        fs::set_permissions(&tmp, meta.permissions())?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Errors if `path` or its parent directory is a symlink (a hostile repo can plant one to redirect a write).
pub fn reject_symlinks(path: &Path) -> Result<(), SentrisError> {
    let is_link = |p: &Path| {
        fs::symlink_metadata(p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    };
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if is_link(path) || parent.is_some_and(is_link) {
        return Err(SentrisError::Scan(format!(
            "Refusing to use symlinked path: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Splits `s` into (text, line ending) for one `split_inclusive('\n')` segment.
pub fn split_eol(seg: &str) -> (&str, &str) {
    if let Some(body) = seg.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = seg.strip_suffix('\n') {
        (body, "\n")
    } else {
        (seg, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_content_keeps_mode_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&f, fs::Permissions::from_mode(0o640)).unwrap();
        }
        write_atomic(&f, "new").unwrap();
        assert_eq!(fs::read_to_string(&f).unwrap(), "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks_and_leaves_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        fs::write(&real, "keep").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(write_atomic(&link, "evil").is_err());
        assert_eq!(fs::read_to_string(&real).unwrap(), "keep");
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlinks_flags_file_and_parent_links() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("dirlink")).unwrap();
        std::os::unix::fs::symlink(real.join("x"), real.join("filelink")).unwrap();
        assert!(reject_symlinks(&dir.path().join("dirlink").join("ledger.json")).is_err());
        assert!(reject_symlinks(&real.join("filelink")).is_err());
        assert!(reject_symlinks(&real.join("ledger.json")).is_ok());
    }

    #[test]
    fn failed_write_keeps_original_and_cleans_temp() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.txt");
        assert!(write_atomic(&missing, "x").is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
