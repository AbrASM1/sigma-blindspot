# sigma-blindspot

Static analyzer that proves which Sigma rules can never fire under a given Sysmon configuration,
and points to the configuration line responsible.

Status: v0.1. The Sysmon configuration parser and the reference filtering emulator are in place.
Sigma loading and the Z3 prover are not implemented yet: the tool gives no verdict on Sigma rules
today.

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
  one object per line:
  `{"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"}`.
  Field values are strings, as in the Sysmon `EventData`.

Configuration and event files are read as UTF-8, with or without a byte order mark, or as UTF-16
with a byte order mark. The XML encoding declaration is ignored and a `DOCTYPE` declaration is
rejected.
Output is ASCII-only. Exit codes: `0` success, `1` a `doctor` check failed or the reader closed
the output early, `2` invalid input.

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

The configuration parser is strict: unknown attributes, a missing `onmatch` or `groupRelation`,
an unknown condition, an empty `<Rule>` or text where only elements belong raise an error with
the file and line, instead of guessing what Sysmon would do.

## Development

```console
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```
