# Jev v2: ask about files before reading them all

## What we want

Ship a small Pi helper through `lgtm init --agent pi`, built on the
existing `jev-auto.ts` approach. Use Pi's built-in Jev support and the
user's configured OpenRouter credentials—not a separate router package.

## The simple idea

A normal read puts file text in the main model's context. A Jev file
question sends that text to Jev instead. The main model gets a short
answer and probability.

Example: “Does this file run policy checks, or only define policy data?”

1. Find a short list of candidate file paths.
2. The helper reads those files and asks Jev the question.
3. Return paths, answers, probabilities, and any skipped/truncated status.
4. The main model reads the useful files normally before editing or quoting.

The file-question operation should also work inside native codemode.
It is an explicit tool, not a hidden replacement for every read.

## When it helps

Use it to scout many files for meaning without loading all their text.
Use grep for exact strings and code for counting.

For focused code investigation, CodeGraph may already be enough.
Its `explore` output includes source: filtering after that source reaches
the main model is too late to save those context tokens.

## Keep it safe and optional

- Keep uncertain files available for a normal read. A low score is not proof.
- Bound file sizes, candidate counts, concurrency, and request time.
- Exclude credentials; enforce workspace paths and report incomplete reads.
- Missing authentication or a failed request must leave normal reads and
  LGTM's deterministic enforcement usable.
- Init installs the capability; it does not send files or require an API key.
- Existing auto-routing and its enablement are separate from this new tool.

## Status

This is a proposal, not a shipped feature. Our routing/build benchmarks did
not test Jev file reads. Compare it with CodeGraph/grep alone, including
missed files, cached-input prices, later full reads, and elapsed time.

Reference: [10 Levels of Jev, Levels 8–9](https://github.com/disler/ten-levels-of-jev).
