# Codex adapter

LGTM policy execution is harness-neutral. Codex and other agents can use the
same deterministic entry point:

```bash
lgtm check --tier full
```

The command uses the same policy selection, bounded runners, evidence schema,
waiver handling, and exit semantics as lifecycle hooks. Exit status `0` means
no unresolved error-severity MUST result; `2` means a policy block. Missing
tools remain `unverified`.

The repository workflow in `.github/workflows/lgtm.yml` is the supported
Codex/CI integration. It pins `--locked`, runs the full tier, and uploads the
bounded log artifact. Codex does not receive Claude-specific lifecycle hooks;
prompt/session context injection and interactive PreToolUse behavior are
platform limitations. Agents must not invent replacement statuses or claim
checks passed without matching evidence.
