# P3: several filters with the same tag and onmatch

Question: when two `<ProcessCreate onmatch="include">` filters sit in different RuleGroups, does
Sysmon combine them with OR? sigma-blindspot assumes it does.

The first filter includes command lines containing the marker of line 1, the second the marker
of line 2. The trigger runs `cmd /c rem` with the markers of lines 1, 2 and 3.

Reading the result: the assumption holds if lines 1 and 2 are `LOGGED` and line 3 `DROPPED`. If
only one of lines 1 and 2 is logged, Sysmon keeps a single filter per tag.
