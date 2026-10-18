# Lab kit

Scripts that check the Sysmon behaviour sigma-blindspot assumes, on an isolated Windows VM with
Sysmon installed. Never run them on a workstation: they replace the Sysmon configuration.

Requirements on the VM: Windows PowerShell 5.1 or PowerShell 7 run as administrator,
`Sysmon64.exe` on the `PATH`, `uv` and a checkout of this repository (for the emulator
prediction), and network access to `example.org`.

## Export-SysmonEvents.ps1

```powershell
.\Export-SysmonEvents.ps1 [-Since <datetime>] [-Marker <text>] [-OutFile <path>]
```

Reads `Microsoft-Windows-Sysmon/Operational` and writes one JSON object per event,
`{"EventID": <int>, "<field>": "<string>"}`, UTF-8 without a byte order mark, to
`lab\out\events.jsonl` by default. `sigma-blindspot check-event` reads the file as-is. `-Since`
keeps the events logged since a time, `-Marker` the events with a field containing a text.
Exported events contain host and user names: `lab\out` is ignored by git.

## Invoke-Probe.ps1

```powershell
.\Invoke-Probe.ps1 -Probe <name> -BaselineConfig <path> [-Sysmon <path>] [-WaitSeconds <n>]
```

Runs one probe from `lab\probes\<name>`:

1. Replaces the `MARKER` token in `config.xml` and `expected.jsonl` with a unique marker, in
   `lab\out\<name>-<marker>`.
2. Prints the emulator prediction for each line of `expected.jsonl`
   (`sigma-blindspot check-event`).
3. Applies the probe configuration with `sysmon -c`, runs `trigger.ps1 -Marker <marker>` in a
   child PowerShell, waits, and exports the events logged meanwhile.
4. Always restores `-BaselineConfig` with `sysmon -c`, even after an error.
5. Prints PREDICTED against OBSERVED for each expected event, with the Sysmon version and schema
   version, and writes the table to `lab\out\<name>-<marker>\result.md`.

An expected event is observed when an exported event has the same `EventID` and either a field
containing its `ProbeKey` (a marker such as `MARKER-1`), or, for `ProbeKey` `PID`, a
`ProcessId` or `SourceProcessId` equal to the trigger process. `ProbeMatch` lists fields that
must also be equal, comma-separated. Both keys are ignored by the emulator.

## Probes

| Probe | Question |
| --- | --- |
| `p1-defaults` | What is logged for event types absent from the configuration? |
| `p2-condition-name-case` | Is `condition="Contains"` accepted, and does it behave like `contains`? |
| `p3-several-filters` | Do two filters with the same tag and `onmatch` combine with OR? |
| `p4-legacy-rule` | Does a `<Rule>` in a filter without RuleGroup combine with AND? |
| `p5-less-than`, `p5-more-than` | Do `less than` and `more than` compare text or numbers? |
| `p6-whitespace` | Are leading and trailing spaces in values compared literally? |
| `p7-empty-list-items` | Are empty items of a `;` list ignored? |

Each probe directory has the question and how to read the result in its `README.md`. Triggers
are benign and clean up after themselves: files under `%TEMP%`, keys under
`HKCU\Software\SigmaBlindspotProbe`, connections to `example.org`, a named pipe, a clipboard
write and an alternate data stream.

Paste the content of `result.md` to update the semantics table: each result is kept in
`lab\results\<probe>.md` and flips the matching assumption to `verified`, or changes the
emulator.

## Lint

```powershell
Invoke-ScriptAnalyzer -Path lab -Recurse -Settings lab\PSScriptAnalyzerSettings.psd1
```
