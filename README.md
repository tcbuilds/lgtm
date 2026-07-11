# LGTM

`lgtm` adds automated engineering checks to Claude Code. It checks edits, blocks unresolved policy violations before Claude stops, and records what was actually verified.

The current release supports Python repositories on x86_64 Linux and macOS.

## Quick Start

Install Rust, clone this repository, then install the CLI:

```bash
git clone https://github.com/tcbuilds/lgtm.git
cd lgtm
cargo install --path .
lgtm --version
```

Move to the Python repository you want to protect and initialize LGTM:

```bash
cd ../my-python-project
lgtm init
lgtm doctor
```

`lgtm init` adds the project configuration and Claude Code hooks without replacing existing settings. `lgtm doctor` shows any optional checking tools you still need to install, including `gitleaks`, `ruff`, and `semgrep`.

Commit the generated `.lgtm/config.json`, `.claude/settings.json`, and `.gitignore` changes. Claude Code will run LGTM automatically during future sessions.

## Common Commands

```bash
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
