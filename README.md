# LGTM

`lgtm` adds automated engineering checks to Claude Code. It checks edits, blocks unresolved policy violations before Claude stops, and records what was actually verified.

The current release supports Python repositories on x86_64 Linux and macOS.

## Quick Install

Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/tcbuilds/lgtm/main/scripts/install.sh | sh
lgtm --version
```

This downloads the latest release, verifies its SHA-256 checksum, and installs `lgtm` to `~/.local/bin`. Add that directory to `PATH` if needed:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc # or ~/.zshrc
```

To install from source instead, use Rust:

```bash
cargo install --git https://github.com/tcbuilds/lgtm
```

## Initialize a Project

From the Python repository you want to protect:

```bash
lgtm init
lgtm doctor
```

`lgtm init` adds the project configuration and Claude Code hooks without replacing existing settings. `lgtm doctor` shows any optional checking tools you still need to install, including `gitleaks`, `ruff`, and `semgrep`.

Commit the generated `.lgtm/config.json`, `.claude/settings.json`, and `.gitignore` changes. Claude Code will run LGTM automatically during future sessions.

## Common Commands

```bash
# Check for or install the latest LGTM release
lgtm update --check
lgtm update

# Check that the bundled policy is valid
lgtm compile --validate

# Show the latest verification report
lgtm report

# Show one task from an evidence file
lgtm report --evidence .lgtm/evidence/evidence.jsonl --task TASK_ID

# Create a temporary, audited exception for an eligible rule
lgtm waive --rule RULE_ID --reason "why" --owner OWNER --expires YYYY-MM-DD
```

LGTM reports unavailable checks as `unverified` instead of claiming they passed. Waivers require an owner, reason, and expiration date. Security-critical rules cannot be waived.

## Development

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked
```

Read [AGENTS.md](AGENTS.md) for contribution guidelines and [doc/adr/](doc/adr/) for architecture decisions.
