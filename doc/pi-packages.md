# Pi documentation tools and MCP

## Default setup

LGTM uses Pi's built-in MCP support. It does not install `pi-mcp-extension`.
For library documentation, LGTM installs the official
`npm:@upstash/context7-pi` package instead of `rtfd-pi`.

Project defaults are in `templates/pi/settings.json`. Run
`lgtm init --agent pi` to apply them to `.pi/settings.json`.
Global setup uses `lgtm init --global` and writes
`~/.pi/agent/settings.json`. Global setup adds Context7, but does not add the
full project package list.

## Existing installations

Init and managed-file refresh remove `pi-mcp-extension` and `rtfd-pi` package
entries. This includes versioned entries and entries with resource filters.
They add Context7 when it is missing. An existing Context7 version and its
resource filters stay unchanged. This package migration preserves other packages
and settings. Normal init can still update other LGTM-managed defaults, such as
historical package pins and codemode.

The migration does not change MCP server configuration. If a server still uses
configuration for the old bridge, configure it with Pi's built-in MCP commands.
Removing the bridge package does not convert that server configuration.

Restart Pi after changing packages. Tools already loaded in a session can
remain available until restart.

## Context7 access

The package documentation says that Context7 works without an API key, with
IP-based rate limits. For higher limits, set `CONTEXT7_API_KEY` in your shell.
Do not put a key in repository settings.

Source: <https://www.npmjs.com/package/@upstash/context7-pi>

## Verify

Run these commands from the LGTM source checkout:

```sh
cargo test --test init --test managed_upgrade --test pi_upgrade --test init_global
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Use `pi list` to inspect configured packages. Use `pi mcp list` to check your
MCP server connections. The latter command connects to configured servers.

## Rollback

Restore the previous LGTM binary and settings files. To restore a package
manually, use `pi install npm:rtfd-pi` or
`pi install npm:pi-mcp-extension`. Add `--local` for project scope. A later run
of the new LGTM init or managed refresh removes these retired packages again.
