# argue

An argument cartographer.

You write an argument down in a small explicit format — claims, evidence,
assumptions, counters, warrants, and the support/attack edges between them.
argue maps it, checks its structure, and finds the holes: claims nothing
supports, evidence that supports nothing, circular support, attacks that are
never answered, and parts of the argument that are not connected to the whole.

Single file, Python 3.9+, standard library only. No install step.

```
python argue.py check argument.arg
python argue.py render argument.arg --out map.html
python argue.py review argument.arg --note "v2 after review"
```

## Why write it down at all

You cannot audit reasoning that only exists as a feeling. An argument that lives
in prose hides its own joints: the premise smuggled in as fact, the conclusion
that quietly supports one of its own supports, the counter-example nobody
mentioned. Those are structural faults, and structure is exactly what a tool can
check.

argue does **not** guess your premises from prose. That is deliberate: a tool
that invents your argument for you cannot be trusted to audit it. You state the
structure; argue holds you to it.

## The format

One declaration per line. Blank lines and lines starting with `#` are ignored.

```
# a node:  ID : kind : free text
C1: claim: The migration will ship by Nov 1.
E1: evidence: The last two migrations shipped on time.
A1: assumption: The vendor does not slip again.
X1: counter: The vendor is already two weeks late.
W1: warrant: Past delivery predicts future delivery.

# an edge:  SRC -> DST            (supports, the default)
#           SRC -> DST : attacks  (a rebuttal or counter)
W1 -> C1
E1 -> C1
A1 -> C1
X1 -> C1 : attacks
```

- **id** starts with a letter and may contain letters, digits, `_` and `-`.
- **kind** is one of `claim`, `evidence`, `assumption`, `counter`, `warrant`.
- **text** is everything after the second colon, so it may contain colons.
- An edge with a colon in its target is read as `DST : label`; the label defaults
  to `supports`.

The full worked example ships in [`examples/migration.arg`](examples/migration.arg).

## What it checks

| Rule | Severity | Meaning |
|---|---|---|
| `unknown-reference` | error | an edge points at an id that was never declared |
| `self-loop` | error | a node supports or attacks itself |
| `cyclic-support` | error | circular support: A supports B supports A |
| `unsupported-claim` | error | a claim with nothing supporting it |
| `attack-on-non-claim` | warn | an attack aimed at evidence or a warrant, not a claim |
| `assumption-only` | warn | a claim whose only support is assumptions |
| `dangling-evidence` | warn | evidence that supports nothing |
| `orphan-node` | warn | a node with no edges at all |
| `one-sided` | warn | a supported claim that considers no counter-evidence |
| `unreferenced-counter` | warn | a counter that attacks nothing |

Cycles are found with Tarjan's strongly-connected-components algorithm, so every
circular cluster is reported once, deterministically — not "a cycle was found
somewhere".

## Commands

| Command | What it gives you |
|---|---|
| `selftest` | 48 checks: the parser, all ten rules, exit codes, the chain, the render |
| `check FILE [--json] [--strict]` | Findings. Exit 1 if any **error**; `--strict` makes warnings fail too |
| `graph FILE [--json]` | The nodes and edges, laid out plainly |
| `render FILE --out map.html` | A self-contained HTML map: nodes, support/attack arrows, findings |
| `review FILE [--note N]` | Analyse and append a hash-chained record of the review |
| `history [--json]` | Every recorded review |
| `verify [--json]` | Rebuild the review hash chain; exit 1 if anything is wrong |

`FILE` may be `-` to read from stdin. `--version` works everywhere. `--now ISO`
pins timestamps so a review is reproducible.

## Exit codes

`check` is a linter:

- **0** — no findings (or only warnings, without `--strict`).
- **1** — at least one error, or any finding under `--strict`.
- **2** — the input could not be read or parsed. Nothing is guessed.

## The review ledger

`review` records what you examined and when, in a hash-chained JSONL log at
`~/.argue/ledger.jsonl` (or `$ARGUE_STORE`, or `--store`). Each record stores
the SHA-256 of the document, its node and edge counts, and its finding counts,
chained so a review cannot be quietly rewritten afterwards:

```
hash[n] = sha256(canonical(record[n] minus hash))     # including prev = hash[n-1]
```

`verify` checks sequence contiguity, prev linkage and content hash per record
and reports *all* problems, each named. Editing a record and deleting the oldest
are both caught.

Honest limit: trimming the *tail* of the file is not detectable from inside the
file. Anchor the last hash elsewhere if that matters.

## Design constraints

**No dependencies.** Python 3.9+ standard library. Determinism matters more than
cleverness here: the parser, the SCC detection and the render layout are all
deterministic, so the same document always produces the same findings in the
same order.

**Explicit over inferred.** The tool never invents structure. If it did, it would
be auditing its own guesses rather than your argument.

**The ledger is a text file you own.** One JSON object per line, greppable.

**The map is one file.** `render` produces a single HTML document with an inline
SVG — no scripts, no fonts, no network.

## Verification

| Gate | What it proves | Floor |
|---|---|---|
| `ci/import_gate.py` | zero third-party imports anywhere | — |
| `selftest` | parser, all ten rules, exit codes, chain, render | 48 checks |
| `tests/test_argue.py` | real CLI behaviour over subprocesses | 37 tests |
| `ci/prove_suites_can_fail.py` | the suites fail when the code breaks and pass when restored | — |
| `ci/mutation.py` | 11 real mutants killed, semantically-identical canary survives | 11/11 |

Run them locally from the repo root:

```powershell
python ci/import_gate.py
python argue.py selftest
python tests/test_argue.py
python ci/check_counts.py
python ci/prove_suites_can_fail.py
python ci/mutation.py
```

The mutation sweep works on a scratch copy; the live `argue.py` is hashed before
and after, so a sweep can never leave a mutant behind.

## Limitations

**It checks structure, not truth.** argue can prove an argument is well-formed;
it cannot prove a premise is true. Garbage in, valid-shaped garbage out.

**Findings are prompts, not verdicts.** `one-sided` fires on any supported claim
with no counter attached — in a context where no counter exists, that is a
prompt to say so, not an error.

**The graph is only as honest as the author.** If you omit a premise, argue
cannot miss what was never written.

**Toulmin-lite.** `warrant` is supported as a node kind, but argue does not
enforce a full Toulmin schema.

## Files

| Path | What |
|---|---|
| `argue.py` | The whole tool. Parser, rules, SCC cycles, chain ledger, HTML map, selftest. |
| `examples/migration.arg` | A worked, clean argument. |
| `tests/test_argue.py` | 37 end-to-end tests over subprocesses. |
| `ci/import_gate.py` | Fails if anything imports outside the standard library. |
| `ci/check_counts.py` | Asserts the suite counts meet the CI floors. |
| `ci/prove_suites_can_fail.py` | Breaks the tool on purpose; requires the suites to notice. |
| `ci/mutation.py` | Mutates a throwaway copy and requires the selftest to notice. Canary-guarded. |
| `REPORT.md` | Engineering report: features, verification, and the defects found while building. |
| `.github/workflows/ci.yml` | Both suites, both gates, on Linux, macOS and Windows. |

## Licence

MIT. See [LICENSE](LICENSE).
