# P4: a Rule inside a filter without RuleGroup

Question: inside a filter that has no RuleGroup, does a `<Rule>` combine with the other fields
with AND? sigma-blindspot assumes it does.

The filter includes `cmd.exe` processes (`Image end with \cmd.exe`) whose command line contains
`MARKER-1` or `MARKER-2` (the Rule). The trigger runs `cmd.exe` with `MARKER-1` (line 1),
`cmd.exe` with `MARKER-3` (line 2) and a renamed copy of `cmd.exe` with `MARKER-2` (line 3).

Reading the result: the assumption holds if line 1 is `LOGGED` and lines 2 and 3 `DROPPED`.
Line 3 `LOGGED` means the Rule combines with OR, line 2 `LOGGED` that the Rule is ignored. If
`sysmon -c` rejects the configuration, Sysmon does not allow a Rule outside a RuleGroup.
