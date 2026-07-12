# Universal fixture matrix

`manifest.json` names deterministic root/monorepo cases spanning every
currently detected language family. The fixture tree intentionally contains no
secrets or external network calls. Runtime tests create symlink, FIFO, and
oversize variants in temporary directories because those filesystem objects do
not belong in Git. `missing-tool`, `malformed-config`, and `legacy-config`
remain data-only fixtures so each adapter can exercise its own config path.
