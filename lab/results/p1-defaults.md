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

This first run had no positive control and its trigger stopped at the first failing action, so
only ProcessCreate (1) and ProcessTerminate (5) were recorded from it.

## Second run, with the control

Run right after `p1-control` (`lab/results/p1-control.md`), on the same VM and Sysmon 15.22,
with the trigger that runs each action on its own and logs it:

```text
probe p1-defaults, marker sbprobeca7a2a0daaab
Sysmon 15.22, schema 4.91
| Line | EventID | Key | Predicted | Observed | |
| --- | --- | --- | --- | --- | --- |
| 1 | 1 | sbprobeca7a2a0daaab-1 | UNKNOWN | LOGGED | DIFFER |
| 2 | 2 | sbprobeca7a2a0daaab-2 | UNKNOWN | DROPPED | DIFFER |
| 3 | 3 | PID | DROPPED | DROPPED | agree |
| 4 | 5 | sbprobeca7a2a0daaab-5 | UNKNOWN | LOGGED | DIFFER |
| 5 | 7 | sbprobeca7a2a0daaab-7 | DROPPED | DROPPED | agree |
| 6 | 10 | sbprobeca7a2a0daaab-10 | UNKNOWN | DROPPED | DIFFER |
| 7 | 11 | sbprobeca7a2a0daaab-11 | UNKNOWN | DROPPED | DIFFER |
| 8 | 12 | sbprobeca7a2a0daaab | UNKNOWN | DROPPED | DIFFER |
| 9 | 13 | sbprobeca7a2a0daaab-13 | UNKNOWN | DROPPED | DIFFER |
| 10 | 14 | sbprobeca7a2a0daaab-14 | UNKNOWN | DROPPED | DIFFER |
| 11 | 15 | sbprobeca7a2a0daaab-15 | UNKNOWN | DROPPED | DIFFER |
| 12 | 17 | sbprobeca7a2a0daaab-17 | UNKNOWN | DROPPED | DIFFER |
| 13 | 18 | sbprobeca7a2a0daaab-17 | UNKNOWN | DROPPED | DIFFER |
| 14 | 22 | PID | UNKNOWN | DROPPED | DIFFER |
| 15 | 23 | sbprobeca7a2a0daaab-23 | UNKNOWN | DROPPED | DIFFER |
| 16 | 24 | PID | UNKNOWN | DROPPED | DIFFER |
| 17 | 26 | sbprobeca7a2a0daaab-23 | UNKNOWN | DROPPED | DIFFER |
| 18 | 27 | sbprobeca7a2a0daaab-5 | UNKNOWN | DROPPED | DIFFER |
| 19 | 29 | sbprobeca7a2a0daaab-5 | UNKNOWN | DROPPED | DIFFER |

trigger: events 1, 5, 27, 29: done
trigger: events 2: done
trigger: events 3: done
trigger: events 7: done
trigger: events 10: done
trigger: events 11: done
trigger: events 12, 13, 14: done
trigger: events 15: done
trigger: events 17, 18: done
trigger: events 22: done
trigger: events 23, 26: done
trigger: events 24: done
```

The predictions come from the code on the VM, which predated the first result.

## Reading

Each type below was observed in the control and not here, with every action of the trigger done:

- Logged without a filter: ProcessCreate (1), ProcessTerminate (5).
- Not logged without a filter: FileCreateTime (2), ProcessAccess (10), FileCreate (11),
  RegistryEvent (12 and 13 observed; 14 is the same filter, the trigger does not produce it),
  FileCreateStreamHash (15), PipeEvent (17, 18), DnsQuery (22), FileDelete (23),
  FileExecutableDetected (29).
- NetworkConnect (3) and ImageLoad (7): not logged, as documented.
- Still unknown: ClipboardChange (24, the control needed `<CaptureClipboard/>`),
  FileDeleteDetected (26) and FileBlockExecutable (27), not observed in the control, and the types
  the trigger does not produce: DriverLoad (6), CreateRemoteThread (8), RawAccessRead (9),
  WmiEvent (19 to 21), ProcessTampering (25), FileBlockShredding (28).
