//! Stable, descriptor-pinned reads for independently provisioned artifacts.
//!
//! Production security inputs must not be resolved with a pathname check
//! followed by a second pathname open. On Unix this module walks every path
//! component through retained directory descriptors with `openat(2)`, refuses
//! links, and reads the final regular file twice through one descriptor. The
//! duplicate bounded read plus descriptor metadata fences detect ordinary
//! concurrent in-place mutation; the caller-supplied digest remains the
//! independent content authority.

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::path::Component;
use std::path::Path;

#[cfg(unix)]
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Read one normalized absolute regular file without following any symlink.
///
/// The file is public integrity material rather than a bearer secret, so
/// read permissions and ownership are deployment concerns. Group/other write
/// permission is rejected because a pinned digest should not normalize an
/// obviously mutable production input into an acceptable operating posture.
/// Unix cannot portably inspect an arbitrary path without opening its final
/// node. `O_NONBLOCK | O_NOCTTY` bounds FIFO/terminal behavior, but deployment
/// provisioning must still ensure that an attacker cannot substitute device
/// nodes in the descriptor-pinned directory hierarchy.
#[cfg(unix)]
pub(crate) fn read_stable_pinned_file(
    label: &str,
    path: &Path,
    expected_digest: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    if max_bytes == 0 {
        return Err(format!("{label} byte limit must be positive"));
    }
    let raw_path = path
        .to_str()
        .ok_or_else(|| format!("{label} path must contain valid UTF-8"))?;
    validate_absolute_path(label, path, raw_path)?;
    validate_digest(label, expected_digest)?;
    let file = open_without_links(label, path, raw_path)?;
    read_stable_descriptor(label, file, expected_digest, max_bytes)
}

#[cfg(not(unix))]
pub(crate) fn read_stable_pinned_file(
    label: &str,
    _path: &Path,
    _expected_digest: &str,
    _max_bytes: u64,
) -> Result<Vec<u8>, String> {
    Err(format!(
        "{label} cannot be loaded on this platform without descriptor-pinned no-follow traversal"
    ))
}

#[cfg(unix)]
fn validate_absolute_path(label: &str, path: &Path, raw_path: &str) -> Result<(), String> {
    let components_are_lexically_normal = raw_path.strip_prefix('/').is_some_and(|suffix| {
        !suffix.is_empty()
            && !suffix
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
    });
    if raw_path.len() > 4096
        || !path.is_absolute()
        || raw_path.as_bytes().contains(&0)
        || raw_path.contains('\\')
        || path.file_name().is_none()
        || !components_are_lexically_normal
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(format!("{label} path must be normalized and absolute"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_digest(label: &str, digest: &str) -> Result<(), String> {
    let valid = digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && hex.bytes().any(|byte| byte != b'0')
    });
    if !valid {
        return Err(format!(
            "{label} expected digest must be nonzero sha256:<64 lowercase hex>"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_without_links(label: &str, path: &Path, raw_path: &str) -> Result<File, String> {
    let mut names = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_owned()),
            Component::RootDir => None,
            _ => unreachable!("validated path has only root and normal components"),
        })
        .collect::<Vec<_>>();
    let final_name = names
        .pop()
        .ok_or_else(|| format!("{label} path must name a file"))?;
    let mut parent = open_root(label, raw_path)?;
    for name in names {
        let name = unix_component(label, raw_path, &name)?;
        parent = open_at(
            &parent,
            &name,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_NOCTTY
                | libc::O_CLOEXEC,
        )
        .map_err(|error| map_open_error(label, raw_path, error, false))?;
    }
    let final_name = unix_component(label, raw_path, &final_name)?;
    open_at(
        &parent,
        &final_name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
    )
    .map_err(|error| map_open_error(label, raw_path, error, true))
}

#[cfg(unix)]
fn open_root(label: &str, raw_path: &str) -> Result<File, String> {
    let root = std::ffi::CString::new("/").expect("static root contains no NUL");
    // SAFETY: `root` is NUL terminated, no mode argument is required, and a
    // successful descriptor is transferred immediately into `File`.
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_NOCTTY
                | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
        .map_err(|error| format!("{label} root traversal for {raw_path} failed: {error}"))
}

#[cfg(unix)]
fn open_at(parent: &File, name: &std::ffi::CStr, flags: libc::c_int) -> std::io::Result<File> {
    use std::os::fd::AsRawFd;

    // SAFETY: `name` is NUL terminated, `parent` remains open for the call,
    // and these flags do not require a variadic mode argument.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    file_from_descriptor(descriptor)
}

#[cfg(unix)]
fn file_from_descriptor(descriptor: libc::c_int) -> std::io::Result<File> {
    use std::os::fd::FromRawFd;

    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `open`/`openat` returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(unix)]
fn unix_component(
    label: &str,
    raw_path: &str,
    component: &std::ffi::OsStr,
) -> Result<std::ffi::CString, String> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(component.as_bytes())
        .map_err(|_| format!("{label} path {raw_path} contains a NUL byte"))
}

#[cfg(unix)]
fn map_open_error(
    label: &str,
    raw_path: &str,
    error: std::io::Error,
    final_component: bool,
) -> String {
    if matches!(
        error.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::EMLINK) | Some(libc::ENOTDIR)
    ) {
        if final_component {
            format!("{label} path {raw_path} must end in a regular file, not a symlink")
        } else {
            format!("{label} path {raw_path} must traverse real directories, not symlinks")
        }
    } else {
        format!("{label} path {raw_path} is unavailable: {error}")
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DescriptorIdentity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
fn descriptor_identity(label: &str, file: &File) -> Result<DescriptorIdentity, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("{label} descriptor metadata is unavailable: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} must be a regular file"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "{label} must not be writable by group or other users"
        ));
    }
    Ok(DescriptorIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn read_stable_descriptor(
    label: &str,
    mut file: File,
    expected_digest: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let before = descriptor_identity(label, &file)?;
    if before.length == 0 || before.length > max_bytes {
        return Err(format!(
            "{label} must be non-empty and no larger than {max_bytes} bytes"
        ));
    }

    let first = read_bounded(label, &mut file, max_bytes)?;
    let middle = descriptor_identity(label, &file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("{label} descriptor rewind failed: {error}"))?;
    let second = read_bounded(label, &mut file, max_bytes)?;
    let after = descriptor_identity(label, &file)?;
    if before != middle || middle != after || first != second || first.len() as u64 != before.length
    {
        return Err(format!("{label} changed while being read"));
    }

    let actual_digest = format!("sha256:{:x}", Sha256::digest(&first));
    if actual_digest != expected_digest {
        return Err(format!(
            "{label} digest mismatch: expected {expected_digest}, got {actual_digest}"
        ));
    }
    Ok(first)
}

#[cfg(unix)]
fn read_bounded(label: &str, file: &mut File, max_bytes: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(usize::try_from(max_bytes.min(64 * 1024)).unwrap_or(0));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{label} descriptor read failed: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{label} exceeds the {max_bytes}-byte limit"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::read_stable_pinned_file;
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::path::Path;
    #[cfg(unix)]
    use tempfile::TempDir;

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(bytes))
    }

    #[cfg(unix)]
    #[test]
    fn reads_exact_regular_file_and_rejects_digest_or_size_mismatch() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let path = root.join("artifact.json");
        let bytes = br#"{"contract_kind":"test"}"#;
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_stable_pinned_file("test artifact", &path, &digest(bytes), 4096).unwrap(),
            bytes
        );
        assert!(read_stable_pinned_file(
            "test artifact",
            &path,
            &format!("sha256:{}", "f".repeat(64)),
            4096,
        )
        .unwrap_err()
        .contains("digest mismatch"));
        assert!(
            read_stable_pinned_file("test artifact", &path, &digest(bytes), 1)
                .unwrap_err()
                .contains("no larger")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_linked_components_and_writable_artifacts() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TempDir::new().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        let path = real.join("artifact.json");
        let bytes = b"{}";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let linked_parent = root.join("linked");
        symlink(&real, &linked_parent).unwrap();
        assert!(read_stable_pinned_file(
            "test artifact",
            &linked_parent.join("artifact.json"),
            &digest(bytes),
            4096,
        )
        .unwrap_err()
        .contains("symlink"));

        let linked_file = root.join("linked.json");
        symlink(&path, &linked_file).unwrap();
        assert!(
            read_stable_pinned_file("test artifact", &linked_file, &digest(bytes), 4096,)
                .unwrap_err()
                .contains("symlink")
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            read_stable_pinned_file("test artifact", &path, &digest(bytes), 4096)
                .unwrap_err()
                .contains("writable by group or other")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt;

        let directory = TempDir::new().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        let path = root.join("artifact.pipe");
        let path_bytes = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path_bytes` is NUL terminated and names a fresh path.
        assert_eq!(unsafe { libc::mkfifo(path_bytes.as_ptr(), 0o600) }, 0);
        let error =
            read_stable_pinned_file("test artifact", &path, &digest(b"unused"), 4096).unwrap_err();
        assert!(
            error.contains("regular file") || error.contains("unavailable"),
            "{error}"
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn fails_closed_without_descriptor_pinned_traversal() {
        let path = std::env::current_dir().unwrap().join("artifact.json");
        assert!(
            read_stable_pinned_file("test artifact", &path, &digest(b"{}"), 4096)
                .unwrap_err()
                .contains("cannot be loaded on this platform")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_relative_and_directory_paths() {
        assert!(read_stable_pinned_file(
            "test artifact",
            Path::new("relative.json"),
            &digest(b"{}"),
            4096,
        )
        .unwrap_err()
        .contains("normalized and absolute"));

        let directory = TempDir::new().unwrap();
        let root = fs::canonicalize(directory.path()).unwrap();
        assert!(
            read_stable_pinned_file("test artifact", &root, &digest(b"{}"), 4096)
                .unwrap_err()
                .contains("regular file")
        );
    }
}
