# LGTM

`lgtm` is an agent-neutral engineering-policy compiler and enforcement runtime. It installs repository policy as Claude Code hooks, runs native and wrapped checks, and records evidence instead of treating missing verification as a pass. The v0.1.2 MVP supports Python repositories and Claude Code.

## Prerequisites

The private release installer supports x86_64 Linux and macOS. It requires:

- GitHub CLI (`gh`), authenticated with access to `tcbuilds/lgtm`
- `gitleaks`, `ruff`, and `semgrep` for the wrapped MVP checks
- `$HOME/.local/bin` on `PATH`, or a custom `LGTM_INSTALL_DIR`

Run `lgtm doctor` after installation for missing-tool guidance.

## Install and Initialize

From an authenticated checkout, install the current release:

```sh
gh auth status --hostname github.com
VERSION=v0.1.2 ./scripts/install.sh
lgtm --version
```

The version check should print `lgtm 0.1.2`. Omitting `VERSION` installs the latest private release. Releases are available to authorized users on the [private GitHub releases page](https://github.com/tcbuilds/lgtm/releases).

Initialize a Python repository from its root:

```sh
cd path/to/python-repository
lgtm init
lgtm doctor
```

Initialization creates or merges `.lgtm/config.json` and `.claude/settings.json` and ensures `.lgtm/evidence/` is ignored in `.gitignore`. Hooks create the evidence directory when they first persist results. Existing valid settings and configuration are preserved.

## Key Commands

```sh
lgtm compile --validate
lgtm report
lgtm report --evidence .lgtm/evidence/evidence.jsonl --task TASK_ID
lgtm waive --rule RULE_ID --reason "why" --owner OWNER --expires YYYY-MM-DD
lgtm hook stop
```

Claude Code normally invokes hooks through `.claude/settings.json`; manual hook execution expects the matching JSON event on standard input. Post-edit checks return block decisions for detected violations. The Stop gate runs full checks and exits with status 2 for unresolved MUST failures. Unavailable tools or evidence are reported as `unverified`, not passed; unverified checks remain visible but do not block. Waivers are audited, expire, and cannot cover protected rules.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked
shellcheck scripts/install.sh scripts/test-install.sh
scripts/test-install.sh
```

See [Repository Guidelines](AGENTS.md) and [architecture decisions](doc/adr/README.md) before contributing.
