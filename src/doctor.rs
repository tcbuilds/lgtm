//! Advisory repository health information for `lgtm doctor`.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::discovery::Workspace;

/// One language server relevant to a discovered repository language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanguageServer {
    pub language: &'static str,
    pub command: &'static str,
    pub install: &'static str,
    pub note: Option<&'static str>,
}

/// Advisory result of checking one language-server command without starting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    Ready,
    Missing,
    UnverifiedRustupProxy,
}

const SERVERS: &[LanguageServer] = &[
    LanguageServer {
        language: "cpp",
        command: "clangd",
        install: "https://clangd.llvm.org/installation",
        note: None,
    },
    LanguageServer {
        language: "csharp",
        command: "csharp-ls",
        install: "dotnet tool install -g csharp-ls",
        note: None,
    },
    LanguageServer {
        language: "go",
        command: "gopls",
        install: "go install golang.org/x/tools/gopls@latest",
        note: None,
    },
    LanguageServer {
        language: "jvm",
        command: "jdtls",
        install: "https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation",
        note: Some(
            "JVM recommendation is coarse; it covers Java tooling, not Kotlin-specific servers.",
        ),
    },
    LanguageServer {
        language: "python",
        command: "pyright",
        install: "npm install -g pyright",
        note: None,
    },
    LanguageServer {
        language: "shell",
        command: "bash-language-server",
        install: "npm install -g bash-language-server",
        note: None,
    },
    LanguageServer {
        language: "sql",
        command: "sqls",
        install: "go install github.com/sqls-server/sqls@latest",
        note: None,
    },
    LanguageServer {
        language: "terraform",
        command: "terraform-ls",
        install: "https://github.com/hashicorp/terraform-ls/blob/main/docs/installation.md",
        note: None,
    },
    LanguageServer {
        language: "typescript",
        command: "typescript-language-server",
        install: "npm install -g typescript-language-server typescript",
        note: None,
    },
    LanguageServer {
        language: "rust",
        command: "rust-analyzer",
        install: "rustup component add rust-analyzer",
        note: None,
    },
];

/// Return one deterministic recommendation for each discovered language.
pub fn recommendations(workspaces: &[Workspace]) -> Vec<LanguageServer> {
    let languages: BTreeSet<_> = workspaces
        .iter()
        .map(|workspace| workspace.language.as_str())
        .collect();
    SERVERS
        .iter()
        .filter(|server| languages.contains(server.language))
        .copied()
        .collect()
}

/// Locate an executable using a supplied PATH value without starting it.
///
/// The explicit arguments keep probing deterministic and make tests independent
/// of the host environment. On Unix, regular files must have an execute bit.
pub fn probe_status(
    command: &str,
    path_value: &OsStr,
    is_windows: bool,
    pathext: &OsStr,
) -> ProbeStatus {
    let Some(path) = executable_on_path(command, path_value, is_windows, pathext) else {
        return ProbeStatus::Missing;
    };
    if command == "rust-analyzer" && is_rustup_proxy(&path) {
        ProbeStatus::UnverifiedRustupProxy
    } else {
        ProbeStatus::Ready
    }
}

pub fn executable_on_path(
    command: &str,
    path_value: &OsStr,
    is_windows: bool,
    pathext: &OsStr,
) -> Option<PathBuf> {
    let candidates: Vec<String> = if is_windows && Path::new(command).extension().is_none() {
        pathext
            .to_string_lossy()
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(|extension| format!("{command}{extension}"))
            .collect()
    } else {
        vec![command.to_string()]
    };
    for directory in std::env::split_paths(path_value) {
        for candidate in &candidates {
            let path = directory.join(candidate);
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            if is_windows || executable_unix(&metadata) {
                return Some(path);
            }
        }
    }
    None
}

#[cfg(unix)]
fn executable_unix(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_unix(_: &std::fs::Metadata) -> bool {
    true
}

fn is_rustup_proxy(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_symlink() {
        return false;
    }
    std::fs::read_link(path)
        .ok()
        .and_then(|target| target.file_stem().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().map(str::to_owned))
        .is_some_and(|name| name.eq_ignore_ascii_case("rustup"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(language: &str) -> Workspace {
        Workspace {
            id: language.to_string(),
            language: language.to_string(),
            root: PathBuf::from("."),
            commands: Vec::new(),
            coverage: Vec::new(),
        }
    }

    #[test]
    fn recommendations_are_relevant_deduplicated_and_stable() {
        let recommendations = recommendations(&[
            workspace("rust"),
            workspace("python"),
            workspace("rust"),
            workspace("unknown"),
        ]);
        assert_eq!(
            recommendations
                .iter()
                .map(|server| server.command)
                .collect::<Vec<_>>(),
            ["pyright", "rust-analyzer"]
        );
    }

    #[test]
    fn unknown_languages_have_no_recommendation() {
        assert!(recommendations(&[workspace("haskell")]).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn path_probe_requires_unix_execute_permission() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("lgtm-doctor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("temp directory");
        let command = root.join("server");
        std::fs::write(&command, "server").expect("server file");
        let path = root.as_os_str();
        let empty_pathext = OsStr::new("");
        assert!(executable_on_path("server", path, false, empty_pathext).is_none());
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(
            executable_on_path("server", path, false, empty_pathext),
            Some(command)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    // macOS filesystem path components use a valid Unicode representation, so
    // raw non-UTF-8 path-byte coverage is specific to Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn path_probe_preserves_non_utf8_path_entries() {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(std::ffi::OsString::from_vec(vec![
            b'l', b'g', b't', b'm', b'-', b'd', b'o', b'c', b't', b'o', b'r', b'-', 0x80,
        ]));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("temp directory");
        let command = root.join("server");
        std::fs::write(&command, "server").expect("server file");
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        assert_eq!(
            executable_on_path("server", root.as_os_str(), false, OsStr::new("")),
            Some(command)
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn path_probe_does_not_execute_candidates() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("lgtm-doctor-no-exec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("temp directory");
        let command = root.join("server");
        let marker = root.join("started");
        std::fs::write(
            &command,
            format!("#!/bin/sh\nprintf launched > {}\n", marker.display()),
        )
        .expect("server script");
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        assert_eq!(
            executable_on_path("server", root.as_os_str(), false, OsStr::new("")),
            Some(command)
        );
        assert!(!marker.exists(), "probing must not execute the server");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn rustup_proxy_is_unverified_but_direct_executable_is_ready() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("lgtm-doctor-rustup-proxy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("temp directory");
        let rustup = root.join("rustup");
        let proxy = root.join("rust-analyzer");
        std::fs::write(&rustup, "rustup").expect("rustup fixture");
        std::fs::set_permissions(&rustup, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::os::unix::fs::symlink("rustup", &proxy).expect("rustup proxy");
        assert_eq!(
            probe_status("rust-analyzer", root.as_os_str(), false, OsStr::new("")),
            ProbeStatus::UnverifiedRustupProxy
        );
        std::fs::remove_file(&proxy).expect("remove proxy");
        std::fs::write(&proxy, "direct rust-analyzer").expect("direct fixture");
        std::fs::set_permissions(&proxy, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(
            probe_status("rust-analyzer", root.as_os_str(), false, OsStr::new("")),
            ProbeStatus::Ready
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn path_probe_finds_ready_file_without_starting_it() {
        let root = std::env::temp_dir().join(format!("lgtm-doctor-ready-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).expect("temp directory");
        let bare_command = root.join("server");
        std::fs::write(&bare_command, "server").expect("server file");
        let path = root.as_os_str();
        assert!(
            executable_on_path("server", path, true, OsStr::new(".EXE;.CMD")).is_none(),
            "Windows PATH lookup must not accept an extensionless regular file"
        );
        let command = root.join("server.EXE");
        std::fs::write(&command, "server").expect("server executable");
        assert_eq!(
            executable_on_path("server", path, true, OsStr::new(".EXE;.CMD")),
            Some(command)
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
