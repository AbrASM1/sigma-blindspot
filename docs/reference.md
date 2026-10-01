# Reference

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

## HTML report

`--html FILE` on `inspect` or `check-event` also writes a report: summary counts, one row per
event with its verdict and links to the configuration lines responsible, the parsed
configuration, the event types left to the assumed default, and the assumptions the results
depend on.

- One self-contained file: no JavaScript, no external resource, and a Content Security Policy
  (`default-src 'none'`) that only allows the embedded stylesheet.
- Every string from the inputs is escaped. Control, format and other invisible characters, such
  as a right-to-left override in a file name, are shown as highlighted escapes (`\u202e`).
- The same inputs give the same file byte for byte: no timestamp, and the SHA-256 of each input
  file identifies what was analysed.
- The report never overwrites an input file.

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
