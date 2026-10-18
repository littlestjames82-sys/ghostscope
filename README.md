# GhostScope

**See what a change actually touches, before you review it.**

GhostSlice builds task-centred context bundles from a whole project.
GhostScope builds *change-centred* review packs from a diff: the changed
files in full, their callers and callees in proportion to risk, the tests
that cover them, and a riskiest-first reading order with the reasons
written out. For a human reviewer it is the reading order. For an agent
reviewer it is the prompt, at a fraction of the full-repo token cost.

By Ghost Developer Studio. Working name (see PLAN.md). MIT core planned,
same pattern as GhostSlice / Agent Seatbelt / Ghost Hands. Local only:
no hosting API, no network, no model calls in v0.1.

Position in the Ghost stack: GhostSlice governs what an agent *reads*
for a task, GhostScope governs what a reviewer *reads* for a change,
GhostVerify *checks* a patch, Agent Seatbelt governs what an agent
*does*.

## Status

v0.1 in build. This README documents the interface defined in PLAN.md.
If a command below does not run yet, that is a build gap, not a
different interface: the tests in `tests/` encode this contract and
report the true state.

## Install (planned, from a checkout)

```bash
cd ghostscope
pip install .
ghostscope --help
```

Or without installing, if the core uses the usual src layout:

```bash
PYTHONPATH=src python3 -m ghostscope --help
```

Requires Python 3.10+ and `git` on PATH. Zero dependencies (Python
standard library only), like the rest of the family.

## Quickstart

From inside the project under review (a local git repo):

```bash
# Pack the changes between two refs
ghostscope pack . --base main --head HEAD -o /tmp/review-pack

# Pack staged changes
ghostscope pack . --staged -o /tmp/review-pack

# Pack from a diff file
ghostscope pack . --diff changes.diff -o /tmp/review-pack

# Why is this file in the pack, at this mode?
ghostscope explain /tmp/review-pack src/shared.py   # via MCP: scope_explain
```

A pack is a normal GhostSlice bundle plus two GhostScope files:

```
review-pack/
  manifest.json   GhostSlice manifest (per file: mode, tokens, sha256)
  scope.json      base, head, per-file graph distance, risk reasons
  REVIEW.md       change summary, risk list in order, reading order,
                  token totals (estimates) vs repo total and raw diff
  PROMPT.md       the pack as an agent-ready prompt (Slice presets)
  files/<rel>     changed files full, distance-1 neighbours at
                  signatures, distance-2 at interfaces, covering
                  tests full for changed symbols
```

Validate a pack the same way as any Slice bundle:

```bash
ghostslice check /tmp/review-pack
```

## Risk, with reasons

GhostScope never prints a bare risk score. Every ranked item carries
its reasons, for example:

- `compute_total` in `shared.py`: exported API, 6 callers, covering test present
- `charge` in `billing.py`: no covering test (covering test deleted in this diff)

Reasons come from the import graph and the call graph. Python call
edges are exact (stdlib `ast`, via GhostSlice). Other languages are
import + outline level and are labelled `parser-lite` in the pack;
their covering-test mapping is heuristic and says so.

A profile can mark paths as sensitive so changes there always rank
higher. In `.ghostslice.json`:

```json
{
  "scope": {
    "sensitive_paths": ["src/auth/**", "src/payments/**"]
  }
}
```

There are no built-in sensitive-path guesses beyond what the profile
says.

## `--fit`

```bash
ghostscope pack . --base main --head HEAD --fit 40000 -o /tmp/review-pack
```

Uses GhostSlice's fit ladder, with one rule on top: changed files are
never downgraded. If the pack cannot fit without touching a changed
file, the pack is still written and the exit code is 1.

## What GhostScope does not do (v0.1)

- No GitHub/GitLab API, no PR fetching, no posting comments, no merge
  actions. Local git and diff files only.
- No approvals or review decisions. It states facts (a signature
  changed, a caller was not updated in this diff, a covering test was
  deleted in this diff), each citing file + symbol.
- No style review, no naming opinions, no LLM-written prose.
- It does not apply patches or run tests. It names the covering tests;
  GhostVerify runs them.

## MCP

Stdio MCP server on the GhostSlice pattern, two tools:

- `scope_pack`: build a review pack for a project + git range.
- `scope_explain`: why a file is in a pack, at what mode, with its
  risk reasons.

Payloads are capped summaries, no raw file bodies by default.

## Tests

```bash
PYTHONPATH=src:. python3 -m pytest tests -q
# or, stdlib only (name the modules: the fixture projects under
# tests/fixtures/ contain their own test_*.py files, which are data,
# and tests/conftest.py keeps pytest from collecting them):
PYTHONPATH=.:src python3 -m unittest tests.test_fixtures_static tests.test_pack_integration -v
```

The fixtures under `tests/fixtures/` are planted cases for the
Verification bar in PLAN.md:

- `high_blast_radius`: a one-line change to a function with 6 callers
  must outrank a 220-line change to an isolated file.
- `signature_change_stale_caller`: an exported function gains a
  required parameter and its callers are not updated.
- `deleted_covering_test`: a change whose only covering test is
  deleted in the same diff; the pack must say so in plain words.

`tests/test_fixtures_static.py` validates the fixtures themselves and
passes with no core installed. `tests/test_pack_integration.py` runs
the real CLI and fails (not skips) while the core is missing.

## Examples

See `examples/`:

- `examples/run_demo.sh`: builds a git repo from the high-blast-radius
  fixture and packs it.
- `examples/sample_pack/`: the *shape* of a finished pack (`scope.json`
  + `REVIEW.md`), labelled as a sample, not captured run output.
