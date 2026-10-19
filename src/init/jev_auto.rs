//! Embedded global Jev auto bundle with conservative receipt-based upgrades.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{InitError, fs};
use crate::fsutil::open_regular_file;

const INDEX: &str = include_str!("../../templates/pi/jev-auto.ts");
const GATES: &str = include_str!("../../templates/pi/jev-auto-gates.ts");
const MAX_RECEIPT_BYTES: u64 = 4096;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    Init,
    Refresh,
}

#[derive(Clone, Copy)]
enum Slot {
    Index,
    Gates,
    Receipt,
    LegacyIndex,
    LegacyGates,
    BackupIndex,
    BackupGates,
}

const ALL: [Slot; 7] = [
    Slot::Index,
    Slot::Gates,
    Slot::Receipt,
    Slot::LegacyIndex,
    Slot::LegacyGates,
    Slot::BackupIndex,
    Slot::BackupGates,
];
const PAIR: [(Slot, &str); 2] = [(Slot::Gates, GATES), (Slot::Index, INDEX)];
const LEGACY_PAIR: [(Slot, Slot); 2] = [
    (Slot::LegacyIndex, Slot::BackupIndex),
    (Slot::LegacyGates, Slot::BackupGates),
];

struct Layout {
    home: PathBuf,
    paths: [PathBuf; 7],
}

impl Layout {
    fn new(home: &Path) -> Result<Self, InitError> {
        if !home.is_absolute() {
            return Err(refuse(home, "Jev auto HOME must be absolute"));
        }
        Ok(Self {
            home: home.to_path_buf(),
            paths: [
                ".pi/agent/extensions/jev-auto/index.ts",
                ".pi/agent/extensions/jev-auto/jev-auto-gates.ts",
                ".local/state/lgtm/jev-auto/receipt.json",
                ".pi/agent/extensions/jev-auto.ts",
                ".pi/agent/extensions/jev-auto-gates.ts",
                ".local/state/lgtm/jev-auto/legacy/jev-auto.ts",
                ".local/state/lgtm/jev-auto/legacy/jev-auto-gates.ts",
            ]
            .map(|relative| home.join(relative)),
        })
    }

    fn path(&self, slot: Slot) -> &Path {
        &self.paths[slot as usize]
    }

    fn set_path(&mut self, slot: Slot, path: PathBuf) {
        self.paths[slot as usize] = path;
    }

    fn preflight(&self) -> Result<(), InitError> {
        let paths = self.paths.each_ref().map(PathBuf::as_path);
        fs::preflight_targets(&self.home, &paths)?;
        fs::preflight_file_targets(&paths)
    }

    fn preflight_one(&self, slot: Slot) -> Result<(), InitError> {
        let path = self.path(slot);
        fs::preflight_targets(&self.home, &[path])?;
        fs::preflight_file_targets(&[path])
    }

    fn observe(&self) -> Result<Vec<Option<String>>, InitError> {
        ALL.into_iter().map(|slot| self.read(slot)).collect()
    }

    fn read(&self, slot: Slot) -> Result<Option<String>, InitError> {
        let path = self.path(slot);
        if !matches!(slot, Slot::Receipt) {
            return fs::read_if_exists(path);
        }
        let error = |source| InitError::Read {
            path: path.to_path_buf(),
            source,
        };
        let Some(file) = open_regular_file(path).map_err(error)? else {
            return Ok(None);
        };
        let mut contents = String::new();
        file.take(MAX_RECEIPT_BYTES + 1)
            .read_to_string(&mut contents)
            .map_err(error)?;
        if contents.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(InitError::FileTooLarge {
                path: path.to_path_buf(),
                max_bytes: MAX_RECEIPT_BYTES,
            });
        }
        Ok(Some(contents))
    }
}

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u8,
    index_sha256: String,
    gates_sha256: String,
}

impl Receipt {
    fn current() -> Self {
        Self {
            version: 1,
            index_sha256: digest(INDEX),
            gates_sha256: digest(GATES),
        }
    }

    fn parse(layout: &Layout, contents: Option<&str>) -> Result<Option<Self>, InitError> {
        let Some(contents) = contents else {
            return Ok(None);
        };
        let path = layout.path(Slot::Receipt);
        let receipt: Self = serde_json::from_str(contents).map_err(|_| {
            refuse(
                path,
                "invalid Jev auto receipt; back it up and inspect it before retrying",
            )
        })?;
        let valid_digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        };
        if receipt.version != 1
            || !valid_digest(&receipt.index_sha256)
            || !valid_digest(&receipt.gates_sha256)
        {
            return Err(refuse(
                path,
                "unsupported or invalid Jev auto receipt; back it up and inspect it before retrying",
            ));
        }
        Ok(Some(receipt))
    }

    fn matches(&self, slot: Slot, contents: &str) -> bool {
        let expected = match slot {
            Slot::Index => &self.index_sha256,
            Slot::Gates => &self.gates_sha256,
            _ => return false,
        };
        digest(contents) == *expected
    }
}

fn digest(contents: &str) -> String {
    format!("{:x}", Sha256::digest(contents.as_bytes()))
}

fn content(snapshot: &[Option<String>], slot: Slot) -> Option<&str> {
    snapshot[slot as usize].as_deref()
}

struct Decision {
    publish: bool,
    note: &'static str,
}

fn decide(snapshot: &[Option<String>], receipt: Option<&Receipt>, intent: Intent) -> Decision {
    let current = PAIR
        .iter()
        .all(|(slot, body)| content(snapshot, *slot) == Some(*body));
    let missing = PAIR
        .iter()
        .any(|(slot, _)| content(snapshot, *slot).is_none());
    let empty = PAIR
        .iter()
        .all(|(slot, _)| content(snapshot, *slot).is_none());
    let Some(receipt) = receipt else {
        return if empty || current {
            Decision {
                publish: true,
                note: "installed or adopted embedded global Jev auto",
            }
        } else {
            Decision {
                publish: false,
                note: "Jev auto was NOT installed or upgraded: custom or incomplete bundle without a receipt was preserved. To replace it, back up remaining directory sources outside extensions, remove both directory sources, and run lgtm init",
            }
        };
    };
    let recognized = PAIR.iter().all(|(slot, body)| {
        content(snapshot, *slot).is_none_or(|text| text == *body || receipt.matches(*slot, text))
    });
    if !recognized {
        return Decision {
            publish: false,
            note: "Jev auto was NOT installed or upgraded: custom files and receipt were preserved",
        };
    }
    if missing && intent == Intent::Refresh {
        return Decision {
            publish: false,
            note: "global Jev auto removal was preserved; use lgtm init to restore recognized files",
        };
    }
    let recorded = PAIR
        .iter()
        .all(|(slot, _)| content(snapshot, *slot).is_some_and(|text| receipt.matches(*slot, text)));
    if missing || current || recorded {
        return Decision {
            publish: true,
            note: "installed or refreshed embedded global Jev auto",
        };
    }
    Decision {
        publish: false,
        note: "Jev auto was NOT installed or upgraded: mixed publication preserved; back up the pair, remove it, and run lgtm init to recover",
    }
}

enum Change {
    Write(Slot, Vec<u8>),
    Remove(Slot),
}

impl Change {
    fn slot(&self) -> Slot {
        match self {
            Self::Write(slot, _) | Self::Remove(slot) => *slot,
        }
    }
}

// Fixed and hash-addressed backups share this private directory.
fn legacy_backup_dir(layout: &Layout) -> PathBuf {
    let fixed = layout.path(Slot::BackupIndex);
    fixed.parent().unwrap_or(fixed).to_path_buf()
}

// Preserve different fixed backups and resolve one stable archive for each source.
fn plan_migration(layout: &mut Layout, snapshot: &mut [Option<String>]) -> Result<bool, InitError> {
    let mut present = false;
    for (legacy_slot, backup_slot) in LEGACY_PAIR {
        let Some(actual) = content(snapshot, legacy_slot).map(str::to_owned) else {
            continue;
        };
        present = true;
        let collides = content(snapshot, backup_slot).is_some_and(|backup| backup != actual);
        if collides {
            resolve_hash_backup(layout, snapshot, backup_slot, &actual)?;
        }
    }
    Ok(present)
}

// A deterministic sibling makes retries reuse identical backups without a naming loop.
fn resolve_hash_backup(
    layout: &mut Layout,
    snapshot: &mut [Option<String>],
    backup_slot: Slot,
    actual: &str,
) -> Result<(), InitError> {
    let sibling = {
        let fixed = layout.path(backup_slot);
        let Some(parent) = fixed.parent() else {
            return Err(refuse(fixed, "Jev auto legacy backup has no parent"));
        };
        let Some(name) = fixed.file_name() else {
            return Err(refuse(fixed, "Jev auto legacy backup has no file name"));
        };
        parent.join(format!("{}.{}.bak", name.to_string_lossy(), digest(actual)))
    };
    layout.set_path(backup_slot, sibling);
    layout.preflight_one(backup_slot)?;
    let observed = layout.read(backup_slot)?;
    if observed.as_deref().is_some_and(|text| text != actual) {
        return Err(refuse(
            layout.path(backup_slot),
            "different legacy backup exists at this hash-addressed path; preserve it outside this destination before retrying",
        ));
    }
    snapshot[backup_slot as usize] = observed;
    Ok(())
}

fn changes(
    snapshot: &[Option<String>],
    receipt: Option<&Receipt>,
    migrate: bool,
) -> Result<Vec<Change>, InitError> {
    let mut changes = Vec::new();
    if migrate {
        for (legacy_slot, backup_slot) in LEGACY_PAIR {
            let Some(actual) = content(snapshot, legacy_slot) else {
                continue;
            };
            if content(snapshot, backup_slot).is_none() {
                changes.push(Change::Write(backup_slot, actual.as_bytes().to_vec()));
            }
        }
        for (legacy_slot, _backup_slot) in LEGACY_PAIR {
            if content(snapshot, legacy_slot).is_some() {
                changes.push(Change::Remove(legacy_slot));
            }
        }
    }
    for (slot, body) in PAIR {
        if content(snapshot, slot) != Some(body) {
            changes.push(Change::Write(slot, body.as_bytes().to_vec()));
        }
    }
    let current = Receipt::current();
    if receipt != Some(&current) {
        let bytes = serde_json::to_vec(&current).map_err(|error| {
            refuse(
                Path::new("receipt.json"),
                format!("serialize Jev auto receipt ({error})"),
            )
        })?;
        changes.push(Change::Write(Slot::Receipt, bytes));
    }
    Ok(changes)
}

fn verify(layout: &Layout, snapshot: &[Option<String>], slot: Slot) -> Result<(), InitError> {
    layout.preflight_one(slot)?;
    if layout.read(slot)?.as_deref() != content(snapshot, slot) {
        return Err(refuse(
            layout.path(slot),
            "Jev auto changed concurrently; retry after the other writer finishes",
        ));
    }
    Ok(())
}

fn remove_legacy(
    layout: &Layout,
    snapshot: &[Option<String>],
    slot: Slot,
) -> Result<(), InitError> {
    let backup = match slot {
        Slot::LegacyIndex => Slot::BackupIndex,
        Slot::LegacyGates => Slot::BackupGates,
        _ => unreachable!("only legacy sources are removed"),
    };
    layout.preflight_one(backup)?;
    if layout.read(backup)?.as_deref() != content(snapshot, slot) {
        return Err(refuse(
            layout.path(backup),
            "legacy backup changed concurrently; source was not removed",
        ));
    }
    std::fs::remove_file(layout.path(slot)).map_err(|source| InitError::Write {
        path: layout.path(slot).to_path_buf(),
        source,
    })
}

fn publish(
    layout: &Layout,
    snapshot: &[Option<String>],
    changes: Vec<Change>,
) -> Result<(), InitError> {
    let mut staged = Vec::with_capacity(changes.len());
    for change in &changes {
        let slot = change.slot();
        let path = layout.path(slot);
        if let Change::Write(_, bytes) = change {
            let parent = path
                .parent()
                .ok_or_else(|| refuse(path, "Jev auto target has no parent"))?;
            if matches!(slot, Slot::Receipt | Slot::BackupIndex | Slot::BackupGates) {
                fs::create_private_dir_all(parent)?;
            } else {
                fs::create_dir_all(parent)?;
            }
            staged.push(Some(fs::stage_private_write(path, bytes)?));
        } else {
            staged.push(None);
        }
    }
    layout.preflight()?;
    if layout.observe()? != snapshot {
        return Err(refuse(
            &layout.home,
            "Jev auto changed concurrently; retry after the other writer finishes",
        ));
    }
    for (change, staged) in changes.into_iter().zip(staged) {
        let slot = change.slot();
        let result = verify(layout, snapshot, slot).and_then(|()| match (change, staged) {
            (Change::Write(_, _), Some(file)) => fs::commit_write(file),
            (Change::Remove(_), None) => remove_legacy(layout, snapshot, slot),
            _ => unreachable!("only writes have staged files"),
        });
        if let Err(error) = result {
            return Err(refuse(
                layout.path(slot),
                format!(
                    "Jev auto publication may be partial ({error}); back up affected files outside extensions. Restore a complete recognized layout, or remove {} and {} and move remaining legacy files outside extensions. Keep the receipt and legacy backups, then run lgtm init",
                    layout.path(Slot::Index).display(),
                    layout.path(Slot::Gates).display()
                ),
            ));
        }
    }
    Ok(())
}

fn refuse(path: &Path, reason: impl Into<String>) -> InitError {
    InitError::UnwritableTarget {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

/// CLI installation performs no provider calls and never reads a source checkout.
/// The receipt and file replacements are cooperative checks, not one transaction.
pub fn install(home: &Path, intent: Intent, dry_run: bool) -> Result<String, InitError> {
    let mut layout = Layout::new(home)?;
    layout.preflight()?;
    let mut snapshot = layout.observe()?;
    let receipt = Receipt::parse(&layout, content(&snapshot, Slot::Receipt))?;
    let migrate = plan_migration(&mut layout, &mut snapshot)?;
    let decision = decide(&snapshot, receipt.as_ref(), intent);
    if !decision.publish {
        if migrate {
            return Err(refuse(
                layout.path(Slot::Index),
                format!(
                    "legacy Jev auto files {} and {} cannot be archived into the preserved destination; back up conflicting files outside extensions before retrying",
                    layout.path(Slot::LegacyIndex).display(),
                    layout.path(Slot::LegacyGates).display()
                ),
            ));
        }
        return Ok(decision.note.to_string());
    }
    let changes = changes(&snapshot, receipt.as_ref(), migrate)?;
    let backup_directory = migrate.then(|| legacy_backup_dir(&layout));
    if dry_run {
        let mut note = format!(
            "would install or refresh global Jev auto; {decision_note}",
            decision_note = decision.note
        );
        if let Some(directory) = &backup_directory {
            note.push_str(&format!(
                "; would back up flat legacy files in {}",
                directory.display()
            ));
        }
        return Ok(note);
    }
    if changes.is_empty() {
        return Ok("global Jev auto already current; no files changed".to_string());
    }
    publish(&layout, &snapshot, changes)?;
    let mut note = format!(
        "{} at {}",
        decision.note,
        layout.path(Slot::Index).display()
    );
    if let Some(directory) = &backup_directory {
        note.push_str(&format!(
            "; flat legacy files were backed up in {}",
            directory.display()
        ));
    }
    Ok(note)
}
