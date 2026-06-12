//! Path-safety helpers for confining ceremony-derived names and paths.
//!
//! Ceremony files are authored by third parties and may be downloaded and run
//! by an operator who never inspected them. Any string from a ceremony that
//! ends up on the filesystem — an artifact id used as an output filename, a
//! material's `path:` value — is therefore untrusted and must not be allowed to
//! escape the directory it is meant to live in.
//!
//! Two primitives cover the cases that occur in practice:
//!
//! - [`validate_component`] / [`safe_join`] for a value that must be a single
//!   path component (a bare file or directory name). This is the right tool for
//!   identifiers that become filenames. Because these names are *created* by
//!   the runtime and a ceremony is portable across operating systems, the rules
//!   are the intersection of what every platform accepts (see
//!   [`validate_component`] for the full list).
//! - [`confine`] for a value that may legitimately be a multi-segment relative
//!   path but must stay within a known root (e.g. `keys/root.pem` under the
//!   ceremony directory). This is used for *reading* files that already exist
//!   on the host, so it only enforces containment, not name portability.
//!
//! Both are purely lexical: they never touch the filesystem, so they are safe to
//! call on paths that do not exist yet and cannot be confused by the current
//! working directory. Lexical checks do **not** defend against symlinks placed
//! at the destination — call sites that create files should additionally open
//! with `create_new` (no-follow, no-clobber) so a pre-planted symlink cannot
//! redirect the write.

use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Characters rejected in created filenames beyond the separators.
///
/// This is the set Windows disallows in file and directory names, per
/// Microsoft's "Naming Files, Paths, and Namespaces" documentation; it matches
/// `DISALLOWED_FILENAME_CHARS` in the `typed-path` crate (v0.12, MIT OR
/// Apache-2.0) minus the separators and NUL, which are rejected separately.
/// `:` is the security-relevant one — on NTFS, `name:stream` writes to an
/// alternate data stream and `C:name` is drive-relative — the rest fail or
/// misbehave in shells and UI. Rejected on every platform because the name may
/// be created on one OS and the run directory copied to another.
const ILLEGAL_FILENAME_CHARS: &[char] = &[':', '?', '*', '"', '>', '<', '|'];

/// Names Windows reserves for devices, matched case-insensitively against the
/// portion of the name before the first `.` (`NUL.txt` is reserved too).
///
/// List adapted from `RESERVED_DEVICE_NAMES` in the `typed-path` crate (v0.12,
/// MIT OR Apache-2.0), which extends Microsoft's documented set with `COM0` /
/// `LPT0`. The match-with-extension semantics follow the `sanitize-filename`
/// crate (v0.6, MIT).
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Maximum filename length in bytes (`NAME_MAX` on Linux, the common floor
/// across filesystems).
const MAX_COMPONENT_BYTES: usize = 255;

/// Why a ceremony-supplied name or path was rejected as unsafe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSafetyError {
    /// The value was empty.
    Empty,
    /// The value was absolute, or carried a root / drive prefix, where a
    /// relative path was required.
    NotRelative,
    /// The value escaped its intended root via one or more `..` components.
    Traversal,
    /// A value that had to be a single path component contained a directory
    /// separator (`/` or `\`).
    Separator,
    /// The name contained a character that is not portable in filenames
    /// (one of `: ? * " > < |`, or a control character).
    IllegalCharacter(char),
    /// The name is reserved by Windows for a device (`CON`, `NUL`, `COM1`, …),
    /// with or without an extension.
    ReservedName,
    /// The name ends with a `.` or a space, which Windows strips on creation —
    /// `key.` and `key` would silently alias the same file.
    TrailingDotOrSpace,
    /// The name exceeds 255 bytes, the common filesystem limit for a single
    /// path component.
    TooLong,
}

impl fmt::Display for PathSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathSafetyError::Empty => write!(f, "path is empty"),
            PathSafetyError::NotRelative => {
                write!(f, "path must be relative (no leading '/' or drive prefix)")
            }
            PathSafetyError::Traversal => {
                write!(f, "path escapes its directory via '..'")
            }
            PathSafetyError::Separator => {
                write!(f, "name must not contain a path separator ('/' or '\\')")
            }
            PathSafetyError::IllegalCharacter(c) => {
                write!(f, "name contains {c:?}, which is not portable in filenames")
            }
            PathSafetyError::ReservedName => {
                write!(f, "name is reserved for a device on Windows")
            }
            PathSafetyError::TrailingDotOrSpace => {
                write!(f, "name must not end with '.' or a space")
            }
            PathSafetyError::TooLong => {
                write!(f, "name exceeds {MAX_COMPONENT_BYTES} bytes")
            }
        }
    }
}

impl std::error::Error for PathSafetyError {}

/// Validate that `name` is a safe, portable single path component: a non-empty
/// plain file or directory name that every supported platform accepts and that
/// cannot leave its directory.
///
/// Rejected, in order of checking:
///
/// - the empty string
/// - separators `/` and `\`
/// - `.` and `..`
/// - characters Windows disallows in names (`: ? * " > < |`) and control
///   characters (C0, C1, DEL — these also enable terminal-escape spoofing when
///   a path is echoed)
/// - Windows reserved device names (`CON`, `NUL`, `COM1`, …), with or without
///   an extension
/// - trailing `.` or space (Windows strips them, silently aliasing names)
/// - names longer than 255 bytes (`NAME_MAX`)
/// - anything `Path::components` does not parse as exactly one normal
///   component on the host platform (e.g. a bare drive prefix)
///
/// # Errors
/// Returns a [`PathSafetyError`] describing the first rule the name violates.
pub fn validate_component(name: &str) -> Result<(), PathSafetyError> {
    if name.is_empty() {
        return Err(PathSafetyError::Empty);
    }
    if name.contains('/') || name.contains('\\') {
        return Err(PathSafetyError::Separator);
    }
    if name == "." || name == ".." {
        return Err(PathSafetyError::Traversal);
    }
    // `is_control` covers C0 (0x00-0x1F), DEL, and C1 (0x80-0x9F).
    if let Some(c) = name
        .chars()
        .find(|c| c.is_control() || ILLEGAL_FILENAME_CHARS.contains(c))
    {
        return Err(PathSafetyError::IllegalCharacter(c));
    }
    let stem = name.split('.').next().unwrap_or(name);
    if WINDOWS_RESERVED_NAMES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(stem))
    {
        return Err(PathSafetyError::ReservedName);
    }
    if name.ends_with(['.', ' ']) {
        return Err(PathSafetyError::TrailingDotOrSpace);
    }
    if name.len() > MAX_COMPONENT_BYTES {
        return Err(PathSafetyError::TooLong);
    }
    // Anything that does not resolve to exactly one "normal" component (e.g. a
    // bare drive prefix like `C:` on Windows) is not a plain name.
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(PathSafetyError::NotRelative),
    }
}

/// Returns `true` if `name` is a safe single path component.
///
/// Convenience wrapper over [`validate_component`] for boolean checks.
#[must_use]
pub fn is_safe_component(name: &str) -> bool {
    validate_component(name).is_ok()
}

/// Join a single untrusted `name` onto `base`, guaranteeing the result is a
/// direct child of `base`.
///
/// # Errors
/// Returns a [`PathSafetyError`] if `name` is not a safe single component (see
/// [`validate_component`]).
pub fn safe_join(base: &Path, name: &str) -> Result<PathBuf, PathSafetyError> {
    validate_component(name)?;
    Ok(base.join(name))
}

/// Resolve an untrusted relative `candidate` against `root`, guaranteeing the
/// result stays within `root`.
///
/// Interior `.` and `..` components are normalized lexically; `candidate` is
/// rejected if it is empty, absolute, or if its `..` components would climb
/// above `root`. The returned path is `root` with the normalized, confined
/// remainder appended.
///
/// Unlike [`validate_component`], this does not enforce name portability —
/// it is meant for paths to existing files on the host, where the host's own
/// rules already applied when the file was created.
///
/// # Errors
/// Returns [`PathSafetyError::Empty`] if `candidate` is empty,
/// [`PathSafetyError::NotRelative`] if it is absolute or carries a
/// root/prefix, or [`PathSafetyError::Traversal`] if it escapes `root`.
pub fn confine(root: &Path, candidate: &Path) -> Result<PathBuf, PathSafetyError> {
    if candidate.as_os_str().is_empty() {
        return Err(PathSafetyError::Empty);
    }
    if candidate.is_absolute() {
        return Err(PathSafetyError::NotRelative);
    }

    let mut relative = PathBuf::new();
    let mut depth: usize = 0;
    for component in candidate.components() {
        match component {
            Component::Normal(segment) => {
                relative.push(segment);
                depth = depth.saturating_add(1);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    return Err(PathSafetyError::Traversal);
                }
                relative.pop();
                depth = depth.saturating_sub(1);
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(PathSafetyError::NotRelative);
            }
        }
    }

    Ok(root.join(relative))
}

#[cfg(test)]
mod tests {
    // Several accept/reject vectors below are adapted from the test corpus of
    // the `sanitize-filename` crate (v0.6, MIT), which in turn derives from
    // node-sanitize-filename (ISC). The `confine` normalization cases are
    // adapted from the test suite of the `path-clean` crate (v1.0, MIT OR
    // Apache-2.0).
    use super::*;

    #[test]
    fn accepts_plain_names() {
        assert!(is_safe_component("wrapped_key"));
        assert!(is_safe_component("root_ca_cert.pem"));
        assert!(is_safe_component("share-1"));
        // Unusual but legal everywhere.
        assert!(is_safe_component("résumé"));
        assert!(is_safe_component("semi;colon.js"));
        assert!(is_safe_component("singlequote'.js"));
        assert!(is_safe_component("plus+.js"));
        assert!(is_safe_component(" space at front"));
        assert!(is_safe_component(".period"));
    }

    #[test]
    fn rejects_separators_and_traversal_in_components() {
        assert_eq!(
            validate_component("../etc/passwd"),
            Err(PathSafetyError::Separator)
        );
        assert_eq!(validate_component("a/b"), Err(PathSafetyError::Separator));
        assert_eq!(validate_component("a\\b"), Err(PathSafetyError::Separator));
        assert_eq!(validate_component(".."), Err(PathSafetyError::Traversal));
        assert_eq!(validate_component("."), Err(PathSafetyError::Traversal));
        assert_eq!(validate_component(""), Err(PathSafetyError::Empty));
    }

    #[test]
    fn rejects_absolute_component() {
        // A leading separator makes this contain a separator first.
        assert_eq!(validate_component("/abs"), Err(PathSafetyError::Separator));
    }

    #[test]
    fn rejects_windows_illegal_characters() {
        // `:` is the dangerous one: NTFS alternate data stream / drive-relative.
        assert_eq!(
            validate_component("key.pem:hidden"),
            Err(PathSafetyError::IllegalCharacter(':'))
        );
        assert_eq!(
            validate_component("C:"),
            Err(PathSafetyError::IllegalCharacter(':'))
        );
        for name in [
            "col:on.js",
            "star*.js",
            "question?.js",
            "quote\".js",
            "brack<e>ts.js",
            "p|pes.js",
        ] {
            assert!(
                matches!(
                    validate_component(name),
                    Err(PathSafetyError::IllegalCharacter(_))
                ),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_control_characters() {
        assert_eq!(
            validate_component("hello\u{0000}world"),
            Err(PathSafetyError::IllegalCharacter('\u{0000}'))
        );
        assert_eq!(
            validate_component("hello\nworld"),
            Err(PathSafetyError::IllegalCharacter('\n'))
        );
        // ANSI escape, the terminal-spoofing vector.
        assert_eq!(
            validate_component("key\u{001b}[2K.pem"),
            Err(PathSafetyError::IllegalCharacter('\u{001b}'))
        );
        // C1 range.
        assert_eq!(
            validate_component("a\u{0085}b"),
            Err(PathSafetyError::IllegalCharacter('\u{0085}'))
        );
    }

    #[test]
    fn rejects_windows_reserved_device_names() {
        for name in ["CON", "con", "NUL", "nul.txt", "LPT9.asdf", "COM1.tar.gz"] {
            assert_eq!(
                validate_component(name),
                Err(PathSafetyError::ReservedName),
                "{name:?} should be rejected"
            );
        }
        // Longer names and different stems are fine.
        assert!(is_safe_component("CONSOLE"));
        assert!(is_safe_component("null.txt"));
        assert!(is_safe_component("com.example"));
        assert!(is_safe_component("communication"));
    }

    #[test]
    fn rejects_trailing_dot_or_space() {
        assert_eq!(
            validate_component("period."),
            Err(PathSafetyError::TrailingDotOrSpace)
        );
        assert_eq!(
            validate_component("space at end "),
            Err(PathSafetyError::TrailingDotOrSpace)
        );
        assert_eq!(
            validate_component("foobar..."),
            Err(PathSafetyError::TrailingDotOrSpace)
        );
    }

    #[test]
    fn rejects_overlong_names() {
        let long = "a".repeat(300);
        assert_eq!(validate_component(&long), Err(PathSafetyError::TooLong));
        let max = "a".repeat(255);
        assert!(is_safe_component(&max));
    }

    #[test]
    fn safe_join_confines_to_base() {
        let base = Path::new("/runs/c/artifacts");
        assert_eq!(
            safe_join(base, "key.pem").unwrap(),
            PathBuf::from("/runs/c/artifacts/key.pem")
        );
        assert!(safe_join(base, "../../etc/passwd").is_err());
        assert!(safe_join(base, "/etc/passwd").is_err());
    }

    #[test]
    fn confine_allows_subpaths() {
        let root = Path::new("/ceremony");
        assert_eq!(
            confine(root, Path::new("keys/root.pem")).unwrap(),
            PathBuf::from("/ceremony/keys/root.pem")
        );
        // Interior `.`/`..` that stays within root is normalized, not rejected.
        assert_eq!(
            confine(root, Path::new("keys/../keys/root.pem")).unwrap(),
            PathBuf::from("/ceremony/keys/root.pem")
        );
        assert_eq!(
            confine(root, Path::new("./root.pem")).unwrap(),
            PathBuf::from("/ceremony/root.pem")
        );
    }

    #[test]
    fn confine_normalizes_like_path_clean() {
        let root = Path::new("/ceremony");
        // Repeated separators collapse.
        assert_eq!(
            confine(root, Path::new("path//to///thing")).unwrap(),
            PathBuf::from("/ceremony/path/to/thing")
        );
        // `.` segments vanish wherever they appear.
        assert_eq!(
            confine(root, Path::new("./test/./path")).unwrap(),
            PathBuf::from("/ceremony/test/path")
        );
        assert_eq!(
            confine(root, Path::new("test/path/.")).unwrap(),
            PathBuf::from("/ceremony/test/path")
        );
        // Trailing separators are ignored.
        assert_eq!(
            confine(root, Path::new("test/path/")).unwrap(),
            PathBuf::from("/ceremony/test/path")
        );
        // A path that fully cancels out resolves to the root itself.
        assert_eq!(
            confine(root, Path::new("test/path/../../")).unwrap(),
            PathBuf::from("/ceremony")
        );
        assert_eq!(
            confine(root, Path::new(".")).unwrap(),
            PathBuf::from("/ceremony")
        );
    }

    #[test]
    fn confine_rejects_escapes_absolute_and_empty() {
        let root = Path::new("/ceremony");
        assert_eq!(
            confine(root, Path::new("../secret")),
            Err(PathSafetyError::Traversal)
        );
        assert_eq!(
            confine(root, Path::new("keys/../../secret")),
            Err(PathSafetyError::Traversal)
        );
        // Escapes are rejected even when later segments would "come back".
        assert_eq!(
            confine(root, Path::new("../ceremony/keys")),
            Err(PathSafetyError::Traversal)
        );
        assert_eq!(
            confine(root, Path::new("/etc/passwd")),
            Err(PathSafetyError::NotRelative)
        );
        assert_eq!(confine(root, Path::new("")), Err(PathSafetyError::Empty));
    }
}
