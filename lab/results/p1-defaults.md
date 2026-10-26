# P1: defaults of event types absent from the config

Run by the maintainer on 2026-10-26, on a fresh Windows VM with Sysmon 15.22, with
`.\Invoke-Probe.ps1 -Probe p1-defaults`. Raw output:

```text
probe p1-defaults, marker sbprobede6bf6a03029
Sysmon 15.22, schema unknown
| Line | EventID | Key | Predicted | Observed | |
| --- | --- | --- | --- | --- | --- |
| 1 | 1 | sbprobede6bf6a03029-1 | UNKNOWN | LOGGED | DIFFER |
| 2 | 2 | sbprobede6bf6a03029-2 | UNKNOWN | DROPPED | DIFFER |
| 3 | 3 | PID | DROPPED | DROPPED | agree |
| 4 | 5 | sbprobede6bf6a03029-5 | UNKNOWN | LOGGED | DIFFER |
| 5 | 7 | sbprobede6bf6a03029-7 | DROPPED | DROPPED | agree |
| 6 | 10 | sbprobede6bf6a03029-10 | UNKNOWN | DROPPED | DIFFER |
| 7 | 11 | sbprobede6bf6a03029-11 | UNKNOWN | DROPPED | DIFFER |
| 8 | 12 | sbprobede6bf6a03029 | UNKNOWN | DROPPED | DIFFER |
| 9 | 13 | sbprobede6bf6a03029-13 | UNKNOWN | DROPPED | DIFFER |
| 10 | 14 | sbprobede6bf6a03029-14 | UNKNOWN | DROPPED | DIFFER |
| 11 | 15 | sbprobede6bf6a03029-15 | UNKNOWN | DROPPED | DIFFER |
| 12 | 17 | sbprobede6bf6a03029-17 | UNKNOWN | DROPPED | DIFFER |
| 13 | 18 | sbprobede6bf6a03029-17 | UNKNOWN | DROPPED | DIFFER |
| 14 | 22 | PID | UNKNOWN | DROPPED | DIFFER |
| 15 | 23 | sbprobede6bf6a03029-23 | UNKNOWN | DROPPED | DIFFER |
| 16 | 24 | PID | UNKNOWN | DROPPED | DIFFER |
| 17 | 26 | sbprobede6bf6a03029-23 | UNKNOWN | DROPPED | DIFFER |
| 18 | 27 | sbprobede6bf6a03029-5 | UNKNOWN | DROPPED | DIFFER |
| 19 | 29 | sbprobede6bf6a03029-5 | UNKNOWN | DROPPED | DIFFER |
```

`schema unknown`: `Get-Version` did not recognise the output of `Sysmon64 -s` in 15.22; the
probe config itself was accepted.

## Reading

- ProcessCreate (1) and ProcessTerminate (5) are logged without a filter: events were observed.
  `events.py` records them as `LOGGED`.
- NetworkConnect (3) and ImageLoad (7) are not logged, as documented.
- Every other type was not observed. This probe has no positive control, so `DROPPED` can also
  mean that the trigger did not produce the event or that the export did not find it. These
  types stay `UNKNOWN` until probe `p1-control` shows that the same trigger is observed when the
  configuration logs everything.
