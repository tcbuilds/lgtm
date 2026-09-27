# Claude Code staged-commit confirmation

LGTM scans the **staged index**, not unstaged working-tree bytes, before a
supported direct `git commit`. Required repository checks run first. Scanner
errors and incomplete scans block commits. Detected provider credentials, private
keys, and findings from unknown or custom rules are not eligible for approval.
Trusted scanner configuration and ignore rules still apply. Only findings from the default
built-in `generic-api-key` rule can request confirmation.

In Claude's `default` or `acceptEdits` permission mode, eligible findings produce
native PreToolUse `permissionDecision: "ask"`. The prompt names redacted
rule/path/line/candidate identifiers, not secret values or scanner descriptions.
`updatedInput` preserves the other Bash input fields and replaces the command
with the absolute LGTM executable's `guarded-commit --request ...` invocation.
Other permission modes, including missing or unknown modes, deny.

## Exact content, not a waiver

The request contains bounded commit arguments and an expected identity. It is a
**precondition, not an approval token**. No file, transcript entry, `approved`
flag, or previous invocation grants authority. Direct agent requests for the
wrapper are checked again and still require native Ask.

Immediately before executing Git, the wrapper reruns the repository gates and
staged scan. It requires the same pending assessment, including repository,
HEAD, index/tree, arguments, findings, scanner/Git identity, scanner config and
ignore bytes, LGTM policy/config/waivers/execution policy, and session. It also
binds the LGTM executable bytes. Any drift, including becoming clean, requires a
new ordinary commit attempt. It executes fixed allowlisted Git arguments without
a shell, with a 60-second execution deadline. Errors are nonzero; after an
execution timeout or error, inspect HEAD before retrying because Git may already
have created the commit.

Stage separately, then issue one direct commit. Compound shell commands,
repository selectors, content-selection flags, and noncanonical wrapper calls
are unsupported. Confirmation applies only to that commit; it does not disable
secret checking in later hooks or create a rule waiver.

## Trust boundary and limitations

Claude's trusted permission system owns approval. LGTM does not invent an
`interactive` hook field or treat `permission_mode` as proof of a human prompt.
Unattended sessions without a permission decision deny the Ask. Externally
configured PermissionRequest hooks or SDK permission callbacks can make their
own decisions; do not configure automatic approval for this command if human
confirmation is required. See the official
[hooks reference](https://code.claude.com/docs/en/hooks).

This is not an OS sandbox against a malicious same-UID process, an altered hook
configuration, arbitrary indirect execution, or a replacement executable. Git
hooks and concurrent processes can still mutate state after the final check;
revalidation narrows that window but is not an atomic Git transaction. Staged
scanning is added/changed-content coverage, not an audit of all history. Trusted
scanner suppressions remain operator policy.

## Verification and rollout

Run `cargo test --test guarded_commit --test commit_secret_scope` with gitleaks
installed. Tests cover real scanner results and wrapper execution; they do not
prove Claude's native UI behavior.

Before relying on interactive approval, use a disposable repository and the
installed Claude version to verify: the rewritten command is shown at Ask;
Cancel does not commit; confirming unchanged synthetic heuristic content
commits; changing the index while the prompt is open prevents execution; and
headless/bypass-permission runs do not silently authorize unresolved findings.
Native interactive smoke verification remains a manual release check.

Install the rebuilt binary and retain the normal Claude PreToolUse hook. No
approval storage or configuration migration is required. Roll back the binary
and hook together to the previous supported version; unresolved findings then
remain denied rather than approved.
