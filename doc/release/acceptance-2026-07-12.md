# Release acceptance — 2026-07-12

Status: prerelease evidence recorded. Stable release remains gated on external
public-repository dogfood; fixture results are not substituted for that gate.

| Budget | Target | Measured evidence |
| --- | --- | --- |
| Silent passes | 0 | 0 observed; claims require current evidence |
| Unsafe command execution | 0 | argv-only, no-shell, bounded timeout/output tests pass |
| Protected-rule bypasses | 0 | overlay/waiver/organization weakening tests pass |
| Standards mapping | 100% bullets mapped | 100% headings in V2 ledger; many remain partial/review |
| Packet size | configured budget | 5,727–6,931 bytes in 10-task dogfood |
| Fast-hook p95 | ≤250 ms | 27 ms max in fixture explain sample |
| Unsupported findings | explicit count | 13 `unverified` in full-tier local smoke |
| False blocks/misses | documented | 0 observed in fixture scope; external scope open |

Verification commands:

```bash
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo run --locked -- check --tier full
lgtm stats --evidence .lgtm/evidence/evidence.jsonl
```
