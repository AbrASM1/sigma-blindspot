# sigma-blindspot

Static analyzer that proves which Sigma rules can never fire under a given Sysmon
configuration, and points to the config line responsible. Open-source project, solo
maintainer, time-boxed to about 40 hours in total: MVP first, polish later.

## Working agreement

- Converse with the maintainer in French. Write code, comments, docstrings, commits and docs
  in English.
- Before a change that touches more than one module, propose a short plan and wait for approval.
- The maintainer must be able to explain every part of the code. After any non-trivial change,
  give 3 to 5 lines: what changed, why, and which test proves it.
- Ask before adding a runtime dependency, changing the public CLI, or bumping `z3-solver`.
- If a task grows beyond the current milestone, say so and propose a cut.

## Commands

- `uv sync`: install from `uv.lock` (Python 3.12 comes from `.python-version`)
- `uv run pytest`: full test suite, must stay green
- `uv run ruff check .` then `uv run ruff format .`: CI also runs `ruff format --check`
- `uv run mypy`: strict type check of `src` and `tests`, also run by CI
- `HYPOTHESIS_PROFILE=intensive uv run pytest` (PowerShell: set `$env:HYPOTHESIS_PROFILE`):
  10,000 examples per property, for deep checks before a release
- `uv run sigma-blindspot doctor | inspect CONFIG | check-event CONFIG EVENTS`, `--html FILE`
  on the last two also writes a self-contained HTML report
- After any dependency change: run `uv lock` and commit `uv.lock` (CI uses `uv sync --locked`)
- The dev machine is Windows (PowerShell). Lab tests run on a separate Windows VM with Sysmon.

## Non-negotiable rules

1. Never output a verdict that cannot be justified. Unsupported Sigma construct, Z3 timeout or
   unknown semantics gives `UNKNOWN` with a reason. `BLIND` only when Z3 returns UNSAT.
2. The emulator (`SysmonConfig.evaluate`) is the reference. A Z3 encoding is trusted only once it
   agrees with the emulator on generated events (Hypothesis).
3. Undocumented Sysmon behaviour is an assumption: mark it in the code, keep the table
   "Sysmon semantics implemented" in `docs/reference.md` in sync, and flip it to verified only
   after a lab probe.
4. Never invent results. No benchmark figure, percentage or claim in README or docs unless it
   comes from a reproducible command in this repo.
5. Light and fast: the only runtime dependencies are `pysigma` and `z3-solver` (pinned
   `==5.1.0.0` because Z3 performance varies between releases). Everything else is stdlib.
6. Never hand-write a Sigma parser. Use pySigma's parsed condition tree, with modifiers applied.
   A list of maps under a selection means OR; hand-written evaluators often get this wrong.
7. CLI output is ASCII-only (redirected output on Windows uses cp1252). No `print` outside
   `cli.py`.
8. Lab safety: never execute anything under `lab/` on the dev machine (no `sysmon -c`, no attack
   simulation). Write it, lint it (PSScriptAnalyzer if available), and the maintainer runs it on
   the isolated VM. Never commit exported events: `lab/out/` is gitignored because events contain
   hostnames and usernames.
9. Tests never use the network. External data (SigmaHQ, public Sysmon configs) is fetched by
   scripts at pinned commits into the gitignored `.cache/`. Never commit SigmaHQ rules, SigmaHQ
   regression data or third-party Sysmon configs; tests use hand-written `tests/fixtures/`.

## Code conventions

- Python 3.12+, type hints everywhere, `@dataclass(frozen=True, slots=True)` for model objects.
- ruff rules E, F, I, UP, B; line length 100.
- Config problems raise `ConfigError(message, line, source)`. Never swallow exceptions silently.
- Every behaviour change ships with a test; every semantics change also gets a Hypothesis property.
- Tests locate config lines with `conftest.line_of()`, never with hard-coded line numbers.
- Small commits, imperative mood, prefixed `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`.

## Current state (milestone C)

- `src/sigma_blindspot/sysmon/`: `parser.py` (stdlib expat, keeps line numbers, rejects DOCTYPE,
  reads UTF-8 and UTF-16, condition names ignore ASCII case), `model.py` (Event, Condition, Rule,
  EventFilter, Decision with `logged: bool | None`, SysmonConfig = the reference emulator),
  `conditions.py` (the 16 documented operators), `events.py` (tags, event IDs, Sigma category
  mapping, `default_without_filter`: `LOGGED`, `NOT_LOGGED` or `UNKNOWN`), `semantics.py`
  (registry of documented and assumed semantics; `@assumes(...)` marks the code relying on an
  assumption, and a test keeps the table in `docs/reference.md` in sync), `jsonl.py` (reads
  exported events).
- `src/sigma_blindspot/decoding.py`: strict UTF-8 / UTF-16 (byte order mark) decoding shared by
  the config parser and the event reader; expat only ever sees decoded text.
- `src/sigma_blindspot/cli.py`: argparse with `doctor` (checks in `doctor.py`), `inspect`,
  `check-event` (`LOGGED`, `DROPPED` or `UNKNOWN` per event). `errors.py`: `ConfigError` and
  `EventError`, both `(message, line, source)`.
- `src/sigma_blindspot/report/html.py`: pure `render()` of the HTML report (stdlib only, no
  JavaScript, CSP pinned to the embedded stylesheet hash, every input string escaped).
- `src/sigma_blindspot/sigma/`: `ir.py` (LoadedRule with top-level OR branches; And, Or, Not,
  Match, Unsupported; Equals, Prefix, Suffix, Contains, Glob with folded literals), `loader.py`
  (the only module importing pySigma: files and directories, scope check, SKIPPED entries,
  conversion of the parsed tree), `evaluate.py` (three-valued reference evaluator, the oracle of
  the Z3 rule encoding).
- `src/sigma_blindspot/prover/`: `strings.py` (`lit()` / `read()` around `StringVal` escapes,
  nothing beyond U+2FFFF), `encode.py` (the config translated into the rule IR, with the lines
  of each tracked item), `languages.py` (one regular language per pattern, unions factored by
  shape), `search.py` (lazy SMT: Boolean skeleton in Z3; on a justified model, each field is
  checked in Python when simple, else as one regex membership in Z3; minimized conflicts become
  lemmas; A-Z excluded), `prove.py` (verdicts per event ID, branch and rule; one Z3 context per
  rule).
- `tests/`: unit, CLI, property-based and fuzz tests, 317 passing; `test_sources.py` rejects
  hidden characters in tracked files. CI runs on Windows and Linux.

## Sysmon semantics

Documented and implemented: `include` logs only matches, `exclude` logs everything but matches,
exclude always wins; an empty include logs nothing, an empty exclude logs everything; RuleGroup
`groupRelation` sets AND/OR between a filter's items; without RuleGroup, same field is OR and
different fields are AND; every condition is case-insensitive; `;` separates multi-values; the
default condition is `is`; `image` matches a full path or the bare image name; without a filter,
NetworkConnect (3) and ImageLoad (7) are not logged. The default of every other event type
without a filter is `UNKNOWN` until probe P1.

Assumed, to verify with lab probes: condition names ignoring ASCII case; `less than` / `more than`
lexical; leading or trailing whitespace in values compared literally; several filters with the
same tag and onmatch combined with OR; `<Rule>` inside a legacy filter combined with AND; `<Rule>`
combining its conditions with its own `groupRelation`; a condition on a field the event lacks
never matching; empty items of a `;` list ignored; case-insensitivity following the Unicode
lower-case mapping; events carrying every field the config or a rule names (prover).

## Roadmap, in order

One milestone at a time: post a plan, wait for the OK, run the full CI sequence (`ruff check`,
`ruff format --check`, `mypy`, `pytest`, `doctor`), give the summary, commit. `report/html.py`, the
text output of `inspect` and `check-event`, and `decoding.py` are frozen until E (bug fixes only).

- [x] v0.1: Sysmon parser, reference emulator, property tests, CI.
- [x] 0. Condition names ignore ASCII case; three-state default for event types without filter.
- [x] B. Sigma loading in `sigma/`: `loader.py` (files and directories, a broken or out-of-scope
  file is SKIPPED with a reason, never an abort), `ir.py` (And, Or, Not, Match, Unsupported;
  Equals, Prefix, Suffix, Contains, Glob with folded literals), `evaluate.py` (reference
  evaluator). Built from pySigma's parsed tree, never from YAML.
- [x] C. Z3 prover in `prover/`: lazy SMT over a Boolean skeleton with one regex membership per
  field (several memberships on one string make Z3 time out), values searched without A-Z (no
  case folding in Z3), SAT confirmed by the emulator and the evaluator, lines from
  `assert_and_track` cores with `core.minimize`. Verdicts per event ID, PARTIAL per top-level OR
  branch, one Z3 context per rule (results do not depend on rule order), 2000 ms per check.
- [ ] C2. `analyze CONFIG RULES... [--format text|json] [--fail-on-blind] [--timeout-ms N]
  [--jobs N]`: exit 0, 1 (BLIND or PARTIAL with `--fail-on-blind`), 2 (invalid config).
- [ ] A. Lab kit in `lab/` (PowerShell 5.1 and 7): `Export-SysmonEvents.ps1`, `Invoke-Probe.ps1`,
  probes P1 (defaults) to P7; raw results in `lab/results/<probe>.md`.
- [ ] D. SigmaHQ regression validation: `scripts/fetch_sigmahq.py` at a pinned commit; the
  evaluator, the rule encoding and the prover checked against the JSON samples; manual workflow.
- [ ] E. Reports: `--format markdown`, `--format sarif` (2.1.0), `--navigator FILE`.
- [ ] F. Benchmark `bench/run.py`, only after D passes and P1 is resolved; the maintainer approves
  the numbers before `bench/results.md` is committed.
- Out of scope: regex, CIDR and null support; a field check against the Sysmon schema; PyPI.
- Done: BLIND verdicts with lines on SwiftOnSecurity and SigmaHQ, every OK confirmed,
  differential properties pass the intensive profile, D passes or every mismatch is explained,
  P1 resolved, README with real output, tag `v0.2.0`.
