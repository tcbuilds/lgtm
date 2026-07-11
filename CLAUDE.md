# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project State

**Spec stage — no code exists yet.** This repo will become `lgtm`: an agent-neutral policy compiler and enforcement runtime, shipped as a single Rust binary, that converts coding standards into task-specific instructions, hooks, automated checks, and verifiable evidence for AI coding agents.

Two source documents:

- `idea.md` — the **finalized spec** (refined 2026-07-11 via interactive Q&A). Read this first. Its "Key Decisions (Resolved)" table locks 16 architectural choices — do not re-litigate them; treat them as settled unless the user explicitly reopens one.
- `codingStandards.md` — the human-readable engineering standard (Coding Standards V2). This is the **source material** the policy registry (`policy/rules.json`) will be derived from, not general guidance for working in this repo. Sections map to rule categories; each standard gets one or more stable rule IDs.

## Locked Decisions (summary — full table in idea.md)

- **Rust single binary** (~5ms hook startup, per-repo version pinning, no venv in consumer repos).
- **Python-only** enforced rules in MVP; TypeScript fast follow.
- **Claude Code adapter first**, wiring all five native hook events (SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop). Codex adapter post-MVP.
- **Hard-blocking Stop gate** (exit 2) on unresolved MUST violations. No waiver machinery in MVP — only severity overrides on `overridable: true` rules; security-critical rules are non-overridable.
- **Wrap existing tools** as check backends (gitleaks, ruff, semgrep) + native Rust git-diff checks. Missing tool → rule reports `unverified`, never a silent pass.
- **Embedded policy registry** — default `rules.json` compiled into the binary; consumer repos hold only `.lgtm/config.json` (profile, overrides, commands) + gitignored `.lgtm/evidence/`.
- **Deterministic task-context detection** — file paths, diff content, imports, prompt keyword match. No LLM calls inside hooks.
- Adoption via `lgtm init` (merges hook entries into `.claude/settings.json`, never clobbers). `lgtm doctor` reports missing wrapped tools.

## Architecture (planned, from idea.md)

Pipeline: human standards → embedded policy registry → compiler (rule selection from deterministic task context) → two outputs per task: a compact agent-instruction packet (injected via hooks, never the full standards doc) and an executable enforcement plan (fast checks after each edit → targeted checks per slice → full checks at Stop). Every check normalizes to a structured enforcement-result JSON; every task writes an evidence JSONL record. Core is agent-neutral; per-agent adapters (`src/adapters/`) translate the lifecycle into each agent's hook mechanisms.

Planned crate layout: `src/{policy,select,compile,context,checks/{wrapped,diff},evidence,adapters/claude_code}` with canonical `policy/rules.json` + `policy/profiles/` and JSON schemas in `schemas/`. CLI subcommands: `init`, `hook <event>`, `doctor`, `compile`, `report`.

## Working in This Repo

- When implementation starts: standard Cargo workflow (`cargo build`, `cargo test`, `cargo clippy`). Update this file with real commands once `Cargo.toml` exists.
- Open questions (tracked in idea.md, decide at build time, don't guess): dogfood repo pick (internal-python-repo vs alternate-python-repo), binary distribution channel (GitHub releases vs cargo-only), prompt-keyword → intent taxonomy.
- Rollout plan: dogfood on one active Python revenue repo before any adapter beyond Claude Code.
- Non-goals (from idea.md): not a general-purpose linter, not a replacement for language-native tooling, not a giant permanent system prompt. lgtm orchestrates existing tools and requires honest evidence.
