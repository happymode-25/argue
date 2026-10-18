# argue — engineering report

What was built, what was verified, and what broke on the way.

Version 1.0.0. One file, `argue.py`, Python 3.9+, standard library only.

## What it does

An argument cartographer. You describe an argument in an explicit line format
(nodes for claims, evidence, assumptions, counters and warrants; edges for
support and attack). argue parses it into a graph, checks it against ten
structural rules, renders a self-contained SVG map, and keeps a hash-chained
log of every review.

Commands: `check`, `graph`, `render`, `review`, `history`, `verify`, `selftest`.

## Verification

Everything below was run locally on Windows (Python 3.12) and is enforced in CI
on Python 3.9, 3.11 and 3.13 across Linux, macOS and Windows.

| Gate | Command | Result |
|---|---|---|
| Import gate | `python ci/import_gate.py` | no non-stdlib imports |
| Selftest | `python argue.py selftest` | 48 checks, all pass |
| End-to-end | `python tests/test_argue.py` | 37 tests, all pass |
| Count floors | `python ci/check_counts.py` | selftest ≥ 48, e2e ≥ 37 |
| Fail-proof | `python ci/prove_suites_can_fail.py` | both suites fail as named checks, then restored |
| Mutation sweep | `python ci/mutation.py` | 11/11 mutants killed, canary survived |

### The mutation sweep

Each mutant is a one-line change that disables one analysis rule or corrupts the
exit code. The sweep applies it to a scratch copy, compiles it, and requires the
selftest to fail. A semantically-identical canary must survive.

| # | Mutant | Killed by |
|---|---|---|
| 1 | unknown references ignored | `unknown reference detected` |
| 2 | self loops ignored | `self loop detected` |
| 3 | attacks on non-claims ignored | `attack on a non-claim detected` |
| 4 | cycles never reported | `circular support detected` |
| 5 | unsupported claims never reported | `unsupported claim detected` |
| 6 | assumption-only never reported | `assumption-only claim detected` |
| 7 | one-sided claims never reported | `one-sided claim detected` |
| 8 | dangling evidence never reported | `dangling evidence detected` |
| 9 | unreferenced counters never reported | `unreferenced counter detected` |
| 10 | orphan nodes never reported | `orphan node detected` |
| 11 | errors no longer affect the exit code | `document with an error exits 1` |
| — | canary: drop a return annotation | survived (as required) |

The live `argue.py` is hashed before and after the sweep; the harness fails if it
changed.

### The fail-proof gate

`ci/prove_suites_can_fail.py` breaks the tool two ways and requires the suites to
notice, then restores the source in a `finally`:

1. **Behaviour.** Disable the unsupported-claim rule. The selftest must fail with
   the named check `unsupported claim detected`, and the e2e suite must fail too.
2. **Reporting.** Inject `c.ok(False, ...)` at the end of `selftest`. The named
   check `negative control injected by CI` must appear.

## Defects found while building

Both were found during bring-up, by the checks themselves.

### 1. Inline SVG carried an external-looking URL

`render` emitted `<svg xmlns='http://www.w3.org/2000/svg'>`. The selftest asserts
that the rendered map contains no external references, and it failed — correctly.
For an HTML-embedded `<svg>` the `xmlns` attribute is unnecessary; the HTML
parser places the element in the SVG namespace on its own. Dropping it satisfied
both the check and the real requirement (the map is genuinely self-contained).

This is a small thing, but it is the exact class of accident — a document that
looks self-contained but references something — that the constraint exists to
catch.

### 2. A selftest check asserted the wrong rule

Two checks were written against documents that did not exercise the rule they
claimed to. One asserted `attack-on-non-claim` on an edge that was a plain
`supports` self-loop; the other put a "dangling" evidence node that in fact had
two outgoing edges. Both were false failures in the *test*, not the code.

Fixed by constructing documents that actually trigger each rule: a dangling
evidence node is one that something points at but which points at nothing; an
attack on a non-claim is a real `: attacks` edge whose target is not a claim.

## Design notes

**Cycles via SCCs.** Circular support is found with Tarjan's
strongly-connected-components algorithm over the `supports` subgraph. Every
component of size > 1 is one circular cluster, reported once, names sorted — so
the output is deterministic and complete rather than "a cycle exists".

**Explicit grammar.** The parser rejects anything it does not fully understand
(unknown kind, unknown label, malformed line, duplicate id) with exit 2 rather
than skipping it. Silently ignoring a line the author wrote would be the worst
possible behaviour for an auditing tool.

**Deterministic everything.** Parser, SCC order, finding sort order and render
layout all depend only on the input. Findings sort by severity, then rule, then
node, then line.

**Fail-closed chain.** The review ledger uses the same hash discipline as the
family's other tools: `hash[n] = sha256(canonical(record minus hash))` with
`prev = hash[n-1]`, genesis = 64 zeros.

## Limitations

- **Structure, not truth.** A well-formed argument can still be wrong.
- **Findings are prompts.** `one-sided` fires whenever a supported claim has no
  counter attached; sometimes the right response is to say there is none.
- **Only as honest as the author.** Omitted premises cannot be detected.
- **Toulmin-lite.** `warrant` is a node kind; the schema is not enforced.
- **No external anchor.** Tail-trimming the ledger is not detectable in-band.

## Files

| Path | What |
|---|---|
| `argue.py` | The tool. Parser, rules, SCC cycles, chain ledger, SVG map, selftest. |
| `examples/migration.arg` | A worked, clean argument. |
| `tests/test_argue.py` | 37 end-to-end tests over subprocesses. |
| `ci/import_gate.py` | Rejects any non-stdlib import. |
| `ci/check_counts.py` | Asserts the suite counts meet the CI floors. |
| `ci/prove_suites_can_fail.py` | Negative control for both suites. |
| `ci/mutation.py` | Canary-guarded mutation sweep. |
| `.github/workflows/ci.yml` | 5-cell matrix plus the gate job. |
