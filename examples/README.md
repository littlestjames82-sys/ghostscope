# GhostScope examples

- `run_demo.sh` - builds a local git repo from
  `tests/fixtures/high_blast_radius` (base commit, then a one-line
  change to a 6-caller function plus a 220-line isolated change) and
  runs `ghostscope pack` on the range if the core is installed.
  Without the core it prints the expected outcome and exits 3.
- `sample_pack/` - the documented *shape* of a finished pack
  (`scope.json`, `REVIEW.md`). Hand-written samples, clearly labelled,
  not captured run output.
