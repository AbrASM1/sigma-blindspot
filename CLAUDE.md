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

## Code conventions

- Python 3.12+, type hints everywhere, `@dataclass(frozen=True, slots=True)` for model objects.
- ruff rules E, F, I, UP, B; line length 100.
- Config problems raise `ConfigError(message, line, source)`. Never swallow exceptions silently.
- Every behaviour change ships with a test; every semantics change also gets a Hypothesis property.
- Tests locate config lines with `conftest.line_of()`, never with hard-coded line numbers.
- Small commits, imperative mood, prefixed `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `chore:`.

## Current state (v0.1)

- `src/sigma_blindspot/sysmon/`: `parser.py` (stdlib expat, keeps line numbers, rejects DOCTYPE,
  reads UTF-8 and UTF-16), `model.py` (Event, Condition, Rule, EventFilter, Decision,
  SysmonConfig = the reference emulator), `conditions.py` (the 16 documented operators),
  `events.py` (tags, event IDs, Sigma category mapping, unverified defaults), `semantics.py`
  (registry of documented and assumed semantics; `@assumes(...)` marks the code relying on an
  assumption, and a test keeps the table in `docs/reference.md` in sync), `jsonl.py` (reads
  exported events).
- `src/sigma_blindspot/decoding.py`: strict UTF-8 / UTF-16 (byte order mark) decoding shared by
  the config parser and the event reader; expat only ever sees decoded text.
- `src/sigma_blindspot/cli.py`: argparse with `doctor` (checks in `doctor.py`), `inspect`,
  `check-event`. `errors.py`: `ConfigError` and `EventError`, both `(message, line, source)`.
- `src/sigma_blindspot/report/html.py`: pure `render()` of the HTML report (stdlib only, no
  JavaScript, CSP pinned to the embedded stylesheet hash, every input string escaped).
- `tests/`: unit, CLI, property-based and fuzz tests, 233 passing. CI runs on Windows and Linux.

## Sysmon semantics

Documented and implemented: `include` logs only matches, `exclude` logs everything but matches,
exclude always wins; an empty include logs nothing, an empty exclude logs everything; RuleGroup
`groupRelation` sets AND/OR between a filter's items; without RuleGroup, same field is OR and
different fields are AND; every condition is case-insensitive; `;` separates multi-values; the
default condition is `is`; `image` matches a full path or the bare image name.

Assumed, to verify with lab probes: what is logged for event types absent from the config
(everything except 3 and 7); `less than` / `more than` numeric or lexical; leading or trailing
whitespace in values compared literally; several filters with the same tag and onmatch combined
with OR; `<Rule>` inside a legacy filter combined with AND; `<Rule>` combining its conditions
with its own `groupRelation`; a condition on a field the event lacks never matching; empty
items of a `;` list ignored; case-insensitivity following the Unicode lower-case mapping.

## Roadmap, in order

- [x] v0.1: Sysmon parser, reference emulator, property tests, CI.
- [ ] A. Lab kit in `lab/`, compatible with Windows PowerShell 5.1 and PowerShell 7.
  - `Export-SysmonEvents.ps1`: reads `Microsoft-Windows-Sysmon/Operational` with `Get-WinEvent`,
    flattens each event's `ToXml()` EventData into `{EventID, <field>: <value>}`, writes JSON
    Lines that `check-event` reads as-is.
  - `Invoke-Probe.ps1 -Probe <name>` using `lab/probes/<name>/` (`config.xml`, `trigger.ps1`,
    `event.json` = the event the trigger should produce, `README.md` = the question tested).
    Steps: emulator prediction on `event.json`; apply the config with `sysmon -c` (admin); run
    the trigger with a unique marker in the command line or file name; search the log for the
    marker; print PREDICTED vs OBSERVED; always restore the baseline config (try/finally).
  - One probe per assumption listed above. Each probe result updates the table in
    `docs/reference.md`.
  - Differential run: the same actions under a log-everything config and under a target
    config; the emulator must predict exactly which events disappear.
- [ ] B. Sigma loading in `src/sigma_blindspot/sigma/`: Windows rules whose category is in
  `SIGMA_CATEGORY_TO_EVENT_IDS`. Correlations, complex regex, `cidr`, `fieldref`, numeric
  comparisons and `cased` give UNKNOWN with a reason until supported.
- [ ] C. Z3 prover in `src/sigma_blindspot/prover/`: one Z3 String per field, lower-cased
  literals, native PrefixOf / SuffixOf / Contains / equality, regex only for inner wildcards.
  Each Sysmon event ID becomes a `logged(event)` formula with `assert_and_track` labels set to
  config lines; push/pop per rule; timeout per query. Verdicts: BLIND, OK (with an example
  event), DISABLED, UNKNOWN, computed per OR branch; the unsat core gives the responsible lines.
- [ ] D. Validation on SigmaHQ `regression_data` (a JSON export sits next to each .evtx): every
  real event of a rule proven BLIND must be dropped by the emulator.
- [ ] E. Reports: Markdown, JSON, SARIF 2.1.0, ATT&CK Navigator layer 4.5; `--fail-on-blind`;
  process pool; cache keyed by config hash.
- [ ] F. Benchmark popular Sysmon configs against SigmaHQ. Publish only reproducible numbers,
  with method and limits. Include-only configs are deliberate noise trade-offs, not bugs.
