# Reference

## Input and output

- Configuration and event files are read as UTF-8, with or without a byte order mark, or as
  UTF-16 with a byte order mark. The XML encoding declaration is ignored.
- A `DOCTYPE` declaration is rejected, so external entities and entity expansion never run.
- The configuration parser is strict: unknown attributes, a missing `onmatch` or `groupRelation`,
  an unknown condition, an empty `<Rule>` or text where only elements belong raise an error
  instead of guessing what Sysmon would do.
- Configuration and event errors go to stderr as `error: FILE:LINE: message`.
- Every command prints only printable ASCII, errors included. Any other character, including a
  control character in a file name, is escaped, so output redirected on Windows (cp1252) stays
  readable and a file name cannot inject terminal escape sequences.
- Exit codes: `0` success, `1` a `doctor` check failed, `analyze --fail-on-blind` found a `BLIND`,
  `MISSED` or `PARTIAL` rule, or the reader closed the output early, `2` invalid input
  (configuration, events, samples, or a rules path that does not exist).

## analyze

`analyze CONFIG RULES...` proves every rule found in `RULES` (files, or directories searched for
`*.yml`) against `CONFIG`.

- Text output: one line per rule, sorted by verdict (`BLIND`, `MISSED`, `PARTIAL`, `RULE_UNSAT`,
  `UNKNOWN`, `OK`, `SKIPPED`) then by path, with the title, the category and its event IDs, the
  reason and the configuration lines responsible. A summary line counts each verdict; `MISSED` is
  counted only with `--samples`.
- `--format json`: `schema_version` (2), `tool` (name and version), `config` (path and
  SHA-256), `samples` (the `--samples` folder, or `null`), `summary` (count per verdict) and
  `results`. Each result has the verdict, the rule path, title, id, category, event IDs, tags,
  reason and lines, an `example` event for `OK`, `PARTIAL` and `MISSED`, `branches` with one
  finding per event ID, and `recorded`: for `MISSED`, each sample event that matches the rule,
  with its file, event ID, the emulator's reason and the configuration lines. Version 2 added
  `MISSED`, `samples` and `recorded`.
- `--format markdown`: the count per verdict, then the `BLIND`, `MISSED` and `PARTIAL` rules
  grouped by responsible configuration line, the lines blinding the most rules first. A rule appears under
  each of its lines; rules without one (an event type not logged without a filter) come last.
  Rule text is escaped, so a title cannot inject Markdown or HTML.
- `--format sarif`: SARIF 2.1.0, one result per `BLIND`, `MISSED` or `PARTIAL` rule. The primary location
  is the first responsible configuration line, or the configuration file when no line is
  responsible; the related locations are the rule file and the other responsible lines, and the
  result carries the rule's tags. The configuration is listed with its SHA-256.
- `--navigator FILE` also writes an ATT&CK Navigator layer (format 4.5, enterprise domain,
  Windows): the techniques of the `attack.tXXXX` tags whose analysed rules are all `BLIND`. A
  technique with one rule that can fire, or that is not decided, is left out. `FILE` is never
  one of the inputs.
- `--samples DIR` checks the rules against real attack samples (see "Recorded attacks").
- `--timeout-ms N` limits each Z3 check (default 2000). `--jobs N` proves rules in N worker
  processes; the output is the same as with one.
- A rule file that fails to load is reported as `SKIPPED` and never stops the analysis.

## HTML report

`--html FILE` on `inspect` or `check-event` also writes a report: summary counts, one row per
event with its verdict and links to the configuration lines responsible, the parsed
configuration, the default of each event type without a filter, and the assumptions the results
depend on.

- One self-contained file: no JavaScript, no external resource, and a Content Security Policy
  (`default-src 'none'`) that only allows the embedded stylesheet.
- Every string from the inputs is escaped. Control, format and other invisible characters, such
  as a right-to-left override in a file name, are shown as highlighted escapes (`\u202e`).
- The same inputs give the same file byte for byte: no timestamp, and the SHA-256 of each input
  file identifies what was analysed.
- The report never overwrites an input file.

## Sigma rules

Rules are loaded with pySigma, and the analysis works on pySigma's parsed condition tree with
modifiers applied. The YAML is never interpreted by hand.

- In scope: `product: windows`, no `service`, and a `category` with Sysmon event IDs, from the
  table of pySigma's Sysmon pipeline (`process_creation` is 1, `registry_event` is 12, 13 and 14).
  Any other rule is `SKIPPED` with the reason.
- A file that fails to load (invalid YAML, unknown modifier, undefined identifier in the
  condition) is `SKIPPED` with the error and never stops the analysis. Correlation and filter
  rules are `SKIPPED`.
- Directories are searched recursively for `*.yml` files, in a stable order.
- Supported: plain values, `contains`, `startswith`, `endswith`, `*` and `?` wildcards anywhere,
  `all`, `neq`, `windash`, the encoding modifiers (`base64`, `base64offset`, `wide`), and numbers,
  compared as strings. Matching is case-insensitive, and the `EventID` field is the event ID.
- Unsupported, each with its own reason: `cased`, `re`, `cidr`, `null`, `exists`, `lt`, `lte`, `gt`,
  `gte`, `fieldref`, boolean values, timestamp modifiers, `expand` placeholders and keyword
  searches.
- A condition is split into top-level OR branches: the alternatives of its outermost `or` or
  `1 of`. A selection, with its lists of values or maps, stays in one branch. Each branch is
  labelled with the selections it uses.

## Verdicts

The prover decides, for each rule and each Sysmon event ID of its category, whether an event can
match the rule and still be logged by the configuration.

| Verdict | Meaning |
| --- | --- |
| `OK` | The rule is not provably blind: Z3 found an example event that matches the rule and is logged, confirmed by the emulator (logged) and the Sigma evaluator (matches). It is not a guarantee that real attacks are logged. |
| `PARTIAL` | `OK`, but some top-level OR branches of the rule can never fire. They are listed with the configuration lines responsible. |
| `BLIND` | No event can match the rule and be logged: Z3 proved it, or the event types are not logged at all. The configuration lines come from a minimized unsatisfiable core. |
| `MISSED` | Only with `--samples`: the prover says `OK` or `PARTIAL`, but every event of SigmaHQ's recorded attack that matches the rule is dropped by the configuration. The configuration lines come from the emulator's decisions on those events. |
| `RULE_UNSAT` | The rule contradicts itself, whatever the configuration. |
| `UNKNOWN` | Not decided, with the reason: unsupported Sigma construct, unverified Sysmon default, Z3 timeout, or a Z3 model that the emulator and the evaluator could not confirm. |
| `SKIPPED` | The rule or file was not analysed (see "Sigma rules"). |

Per event ID, `DISABLED` means the event type is not logged at all: not logged without a filter,
or dropped entirely by the configuration. A rule is `BLIND` when every event ID is `BLIND`,
`DISABLED` or `RULE_UNSAT`, and `OK` when at least one is `OK`.

`BLIND` is a proof; `OK` is not a guarantee that real attacks are logged. `BLIND` holds for every
possible event, within the assumptions listed in "Sysmon semantics implemented". `OK` only shows
one event that matches the rule and is logged, and Z3 is free to build values that no real attack
would produce: a path, a command line or a file name that an attacker would never use. A real
attack matching an `OK` rule can still be dropped by the configuration.

How the verdicts are computed:

- The configuration is translated into the same condition representation as the rules, and every
  Sysmon condition and Sigma value becomes a regular language on one field, with lower-cased
  literals.
- Z3 searches a Boolean skeleton of the rule and the configuration. For each field, the literals
  that the Boolean model needs are checked as a single regular-language membership, and a
  minimized conflict becomes a lemma. One membership per field keeps Z3 fast: several
  memberships on the same string make it time out on real configurations.
- Simple field checks are decided without Z3: a value fixed by `is`, a pattern included in an
  excluded one (`end with .x.net` against an excluded `end with .net`), or a candidate value built
  from the patterns and checked by the evaluator. Z3 decides the rest.
- Values are searched among strings without `A`-`Z`. That set contains every lower-cased value,
  so an unsatisfiable result is still a proof, and case folding never has to be encoded in Z3.
- Each rule is proved in its own Z3 context, so a verdict, its lines and its example do not
  depend on the other rules or on the order they are proved in.
- Each check has a timeout, 2000 ms by default. A timeout gives `UNKNOWN`.

## Recorded attacks

`analyze --samples DIR` reads real attack samples. `DIR` is a SigmaHQ checkout, or any folder
with the same `regression_data` layout: an `info.yml` lists the rule ids it tests
(`rule_metadata`) and its samples (`regression_tests_info`), and each Sysmon sample is the JSON
export next to the `.evtx` file it names. Samples of other providers are ignored, and so is a
sample without its JSON export.

For each `OK` or `PARTIAL` rule with samples, the events of the rule's event IDs are evaluated:

- If at least one event matches the rule, and the emulator drops every event that matches, the
  rule becomes `MISSED` with the reason "SigmaHQ's recorded attack is dropped by the config".
  The lines are those of the emulator's decisions: the exclude conditions that matched, or the
  include filters that did not.
- An event that is logged, or whose emulator decision is `UNKNOWN`, keeps the prover's verdict.
  So does an event that the evaluator cannot decide (unsupported construct) and that is not
  dropped: it might be a matching event that is logged.
- `BLIND`, `RULE_UNSAT`, `UNKNOWN` and `SKIPPED` rules are not changed.

`MISSED` is evidence, not a proof: it shows that one recorded attack is not visible. Another run
of the same attack, with other paths or command lines, may be logged. An invalid `info.yml` or
JSON sample is an error (exit code `2`), like an invalid configuration.

## Validation on SigmaHQ regression data

`uv run python scripts/validate_regression.py` checks the evaluator, the rule encoding and the
prover on real events. It needs network access: it fetches SigmaHQ at a pinned commit (a sparse
clone of `rules/windows` and `regression_data` into `.cache/sigmahq`) and five public Sysmon
configurations pinned by URL and SHA-256 (into `.cache/configs`). Neither is committed; the
tests never use the network.

For every Sysmon sample of a rule in scope (the JSON export next to each `.evtx`):

1. Evaluator: it matches at least the sample's `match_count` events, or one event when the count
   is missing, which is SigmaHQ's own pass criterion.
2. Encoding: for each supported branch that the evaluator matches on a sample event, the Z3
   encoding of the branch with every field pinned to the event's values is satisfiable.
3. Prover: for each configuration that logs a matching sample event, the prover never says
   `BLIND`, `DISABLED` or `RULE_UNSAT` for that event ID.

The report goes to `.cache/regression.md`, and the script exits with 1 on any mismatch. The
manual workflow `SigmaHQ regression` runs it and uploads the report. The samples are positive
detections only: the validation can catch a wrong `BLIND`, not a missed one.

## Sysmon semantics implemented

`documented` rows come from the
[Sysmon documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon). `assumed` rows
are undocumented behaviour, marked with `@assumes` in the code, and become `verified` only after a
lab probe. `tests/test_semantics.py` keeps this table in sync with
`src/sigma_blindspot/sysmon/semantics.py`.

| Behaviour | Status |
| --- | --- |
| `include` logs only the events that match | documented |
| `exclude` logs every event except those that match | documented |
| An `exclude` match overrides an `include` match | documented |
| An empty `include` logs nothing, an empty `exclude` everything | documented |
| RuleGroup `groupRelation` sets AND or OR between filter items | documented |
| Without RuleGroup, the same field combines with OR and different fields with AND | documented |
| Every condition is case-insensitive | documented |
| The default condition is `is` | documented |
| `;` separates the values of the `any` and `all` conditions | documented |
| `image` matches the full path or the bare image name | documented |
| Event IDs 4, 16 and 255 cannot be filtered | documented |
| Without a filter, NetworkConnect (3) and ImageLoad (7) are not logged | documented |
| Without a filter, ProcessCreate (1) and ProcessTerminate (5) are logged (probe P1, Sysmon 15.22) | verified |
| Without a filter, FileCreateTime (2), ProcessAccess (10), FileCreate (11), RegistryEvent (12, 13, 14), FileCreateStreamHash (15), PipeEvent (17, 18), DnsQuery (22), FileDelete (23) and FileExecutableDetected (29) are not logged (probes P1 and P1 control, Sysmon 15.22) | verified |
| Condition names ignore ASCII case: `Contains` is `contains` | assumed |
| `less than` and `more than` compare lower-cased values lexically | assumed |
| Leading and trailing whitespace in values is compared literally | assumed |
| Several filters with the same tag and `onmatch` combine with OR | assumed |
| A `<Rule>` inside a filter without RuleGroup combines with AND | assumed |
| A `<Rule>` is one filter item combining its conditions with its own `groupRelation` | assumed |
| A condition on a field the event does not carry never matches | assumed |
| Empty items in a `;` list are ignored | assumed |
| Case-insensitivity follows the Unicode lower-case mapping | assumed |
| Events carry every field that the config or a rule names for their type | assumed |

## Known limitations

- What Sysmon logs for an event type that the configuration does not mention comes from the
  documentation (NetworkConnect and ImageLoad) and from lab probes P1 and P1 control on Sysmon
  15.22 (`lab/results/`); other Sysmon versions may differ. It is still unknown for DriverLoad
  (6), CreateRemoteThread (8), RawAccessRead (9), WmiEvent (19 to 21), ClipboardChange (24),
  ProcessTampering (25), FileDeleteDetected (26), FileBlockExecutable (27) and FileBlockShredding
  (28): for them `check-event` prints `UNKNOWN` and `inspect` prints `default: unknown`.
- Field names are not checked against the Sysmon schema: a misspelled field is accepted and its
  conditions never match.
- The prover assumes that events carry every field the configuration or the rule names for their
  type (see the table). A rule or a configuration naming a field that Sysmon never emits for that
  type can make a verdict wrong.
- Z3 represents characters up to U+2FFFF. A rule or a configuration with a value beyond it gives
  `UNKNOWN`.
- UTF-16 files need a byte order mark.
