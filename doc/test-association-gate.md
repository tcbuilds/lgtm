# Test-association gate

The diff gate checks for a plausible changed-test association. It does not prove
that a test exercises the changed behavior, and it does not replace coverage or
test-quality checks.

## Classification

The gate uses the registered language packs and the repository's discovered
workspace roots. A source file is matched to a test file only when both files
belong to the same workspace boundary and language pack. The supported packs
are:

- Python: `.py`; `tests/`, `test/`, `test_...`, and `..._test.py` conventions.
- Rust: `.rs`; `tests/`, `test_...`, and `..._test.rs` conventions. A source
  file changed in an inline `#[cfg(test)]` region also counts as its own test
  evidence.
- TypeScript/JavaScript: `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, and `.cjs`;
  `tests/`, `__tests__/`, `.test.`, and `.spec.` conventions.
- Go: `.go`; `tests/` and the Go `..._test.go` convention.
- Java/Kotlin: `.java`, `.kt`, and `.kts`; `src/test/...`, `tests/`, `*Test`,
  `*Tests`, and `*Spec` conventions.
- C#: `.cs`; `tests/`, `Test...`, `...Test`, and `...Tests` conventions.
- C/C++: `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`, and `.hxx`;
  `tests/` and `..._test` conventions.

Documentation, configuration, generated output, vendor trees, and fixture-only
trees are excluded. Common excluded paths include `doc/`, `docs/`, `vendor/`,
`node_modules/`, `fixtures/`, `testdata/`, `generated/`, `dist/`, `build/`,
`target/`, and `coverage/`. Common documentation and configuration suffixes
such as `.md`, `.json`, `.yaml`, `.toml`, and `.lock` are also excluded. Code
configuration names matching `*.config.<ext>`, such as `vite.config.ts`, are
excluded regardless of the source extension.

Filename markers are anchored: `test_` and `test-` must prefix the file stem;
`_test.`, `_tests.`, `.test.`, `.spec.`, `.e2e.`, and `.cy.` must end the stem
before its extension. A directory named `integration` or `integrations` is a
test directory only in a real test context such as `tests/integration/`; a
production path such as `src/integrations/stripe.rs` remains source code.

When a repository contains nested workspaces, the deepest discovered workspace
owns a path. A frontend test cannot satisfy a backend source change merely
because both files are in the same repository. If workspace discovery fails or
a changed file has no supported language pack, the result is `unverified` and
the evidence records the reason; the gate never silently treats it as passed.

## Enforcement and evidence

`PostToolUse` and `Stop` report a missing association as `unverified`; neither
stage blocks solely because this association was not found. The
`regression-test-required` rule applies the same review signal for `bug-fix`
intent. Documentation-only and configuration-only diffs remain outside the
gate. The pre-edit baseline is used by the preserve-unrelated-changes rule, so
changes already present before the session are exempt, while a clean tracked
file modified during the session still requires a touch record.

Association evidence records the changed source paths, changed test paths,
missing source associations, the language/workspace detection basis, and
`coverage_proven=false`. Deleted test paths do not count as test evidence. The
source path of a rename is currently retained as changed test evidence, which
is a known false-pass documented below. A changed test file is evidence of a
plausible association only; semantic coverage remains a separate verification
result.

## Known false-pass paths and enforcement limit

The current evidence model has known false-pass paths. They are documented here,
not repaired in this milestone:

- A test staged as modified or added and then deleted from the working tree is
  still accepted as evidence. Exclusion is computed from an order-dependent
  merge of cached and unstaged status rather than from final working-tree state.
  For example, a staged modification to `tests/value.py` followed by deleting
  that file from the working tree can still satisfy a changed source file.
- The source path of a rename is never excluded. Renaming `tests/value.py` to
  `src/value.py` lets the now-absent old test path satisfy the new source path.
- A diff header that cannot be parsed is treated as an untracked whole-file
  change. A production-only edit to a path containing a space is therefore
  accepted whenever that file has pre-existing inline tests.
- An outer attribute between `#[cfg(test)]` and `mod`, such as
  `#[allow(dead_code)]`, makes an inline-test edit read as an untested source
  change.

These limits are why the gate reports `unverified` rather than blocking when an
association is missing. A redesign of the evidence model is required before
this gate can enforce test association.
