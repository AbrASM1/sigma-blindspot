# sigma-blindspot

Static analyzer that proves which Sigma rules can never fire under a given Sysmon configuration,
and points to the configuration line responsible.

Status: v0.1. The Sysmon configuration parser and the reference filtering emulator are in place.
Sigma loading and the Z3 prover are not implemented yet: the tool gives no verdict on Sigma rules
today. See the [roadmap](#roadmap).

## Install

Requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

```console
uv sync
uv run sigma-blindspot doctor
```

## Usage

```console
uv run sigma-blindspot doctor
uv run sigma-blindspot inspect CONFIG
uv run sigma-blindspot check-event CONFIG EVENTS
```

- `doctor` checks that `pysigma` and `z3-solver` are installed and work.
- `inspect` prints every filter, rule and condition parsed from a Sysmon configuration with its
  line, then the event types left to the default behaviour.
- `check-event` runs exported events through the emulator and prints, for each event, whether
  Sysmon logs or drops it and which configuration lines decide it. `EVENTS` is a JSON Lines file
  with one object per line. Field values are strings, as in the Sysmon `EventData`.

### Example

`sysmon.xml`:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="image">svchost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <NetworkConnect onmatch="include">
      <DestinationPort>443</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

`events.jsonl`:

```json
{"EventID": 1, "Image": "C:\\Windows\\System32\\svchost.exe"}
{"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe"}
{"EventID": 3, "Image": "C:\\Tools\\curl.exe", "DestinationPort": "80"}
{"EventID": 22, "QueryName": "example.org"}
```

```console
$ uv run sigma-blindspot check-event sysmon.xml events.jsonl
events.jsonl:1: EventID 1 DROPPED matched an exclude filter (sysmon.xml:5)
events.jsonl:2: EventID 1 LOGGED matched no exclude filter
events.jsonl:3: EventID 3 DROPPED matched no include filter (sysmon.xml:8)
events.jsonl:4: EventID 22 LOGGED no filter for this event type, assumed default
4 events: 2 logged, 2 dropped
```

## Input and output

- Configuration and event files are read as UTF-8, with or without a byte order mark, or as
  UTF-16 with a byte order mark. The XML encoding declaration is ignored.
- A `DOCTYPE` declaration is rejected, so external entities and entity expansion never run.
- The configuration parser is strict: unknown attributes, a missing `onmatch` or `groupRelation`,
  an unknown condition, an empty `<Rule>` or text where only elements belong raise an error
  instead of guessing what Sysmon would do.
- Configuration and event errors go to stderr as `error: FILE:LINE: message`.
- `doctor`, `inspect` and `check-event` print only printable ASCII, errors included. Any other
  character, including a control character in a file name, is escaped, so output redirected on
  Windows (cp1252) stays readable and a file name cannot inject terminal escape sequences.
- Exit codes: `0` success, `1` a `doctor` check failed or the reader closed the output early,
  `2` invalid input.

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
| Event types absent from the config are logged, except 3 and 7 | assumed |
| `less than` and `more than` compare lower-cased values lexically | assumed |
| Leading and trailing whitespace in values is compared literally | assumed |
| Several filters with the same tag and `onmatch` combine with OR | assumed |
| A `<Rule>` inside a filter without RuleGroup combines with AND | assumed |
| A `<Rule>` is one filter item combining its conditions with its own `groupRelation` | assumed |
| A condition on a field the event does not carry never matches | assumed |
| Empty items in a `;` list are ignored | assumed |
| Case-insensitivity follows the Unicode lower-case mapping | assumed |

## Known limitations

- What Sysmon logs for an event type that the configuration does not mention is an unverified
  assumption (see the table). `inspect` and `check-event` label those decisions
  `assumed default`.
- Field names are not checked against the Sysmon schema: a misspelled field is accepted and its
  conditions never match.
- Condition names must be spelled exactly as documented: `condition="Contains"` is rejected.
- UTF-16 files need a byte order mark.

## Roadmap

- [x] v0.1: Sysmon configuration parser, reference emulator, property tests, CI on Windows and
  Linux.
- [ ] A. Lab kit: export Sysmon events and run one probe per assumed semantic on a real Sysmon.
- [ ] B. Load Windows Sigma rules with pySigma.
- [ ] C. Z3 prover: `BLIND`, `OK`, `DISABLED` or `UNKNOWN` per rule, with the configuration lines
  responsible.
- [ ] D. Validation on the SigmaHQ regression data.
- [ ] E. Reports: Markdown, JSON, SARIF and ATT&CK Navigator layer, `--fail-on-blind`.
- [ ] F. Reproducible benchmark of popular Sysmon configurations.

## Development

```console
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

The suite combines unit, CLI and Hypothesis property tests with structured fuzzing:

- the emulator must agree with an independent reference written from the documented rules;
- a generated configuration rendered to XML, in each supported encoding, must parse back to the
  same model, line numbers included;
- on fuzzed input, the parser may raise only `ConfigError` and the event reader only
  `EventError`, and `check-event` must exit with `0` or `2` and print printable ASCII.

`HYPOTHESIS_PROFILE=intensive uv run pytest` runs every property with 10,000 examples instead of
the default 100.
