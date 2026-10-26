# P1 control: is each P1 action observed when its type is logged?

Run by the maintainer on 2026-10-26, on the same Windows VM with Sysmon 15.22, right before the
second run of `p1-defaults`, with `.\Invoke-Probe.ps1 -Probe p1-control`. Raw output:

```text
probe p1-control, marker sbprobed3461a624abb
Sysmon 15.22, schema 4.91
| Line | EventID | Key | Predicted | Observed | |
| --- | --- | --- | --- | --- | --- |
| 1 | 1 | sbprobed3461a624abb-1 | LOGGED | LOGGED | agree |
| 2 | 2 | sbprobed3461a624abb-2 | LOGGED | LOGGED | agree |
| 3 | 3 | PID | LOGGED | LOGGED | agree |
| 4 | 5 | sbprobed3461a624abb-5 | LOGGED | LOGGED | agree |
| 5 | 7 | sbprobed3461a624abb-7 | LOGGED | LOGGED | agree |
| 6 | 10 | sbprobed3461a624abb-10 | LOGGED | LOGGED | agree |
| 7 | 11 | sbprobed3461a624abb-11 | LOGGED | LOGGED | agree |
| 8 | 12 | sbprobed3461a624abb | LOGGED | LOGGED | agree |
| 9 | 13 | sbprobed3461a624abb-13 | LOGGED | LOGGED | agree |
| 10 | 14 | sbprobed3461a624abb-14 | LOGGED | DROPPED | DIFFER |
| 11 | 15 | sbprobed3461a624abb-15 | LOGGED | LOGGED | agree |
| 12 | 17 | sbprobed3461a624abb-17 | LOGGED | LOGGED | agree |
| 13 | 18 | sbprobed3461a624abb-17 | LOGGED | LOGGED | agree |
| 14 | 22 | PID | LOGGED | LOGGED | agree |
| 15 | 23 | sbprobed3461a624abb-23 | LOGGED | LOGGED | agree |
| 16 | 24 | PID | LOGGED | LOGGED | agree |
| 17 | 26 | sbprobed3461a624abb-23 | LOGGED | DROPPED | DIFFER |
| 18 | 29 | sbprobed3461a624abb-5 | LOGGED | LOGGED | agree |

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

## Reading

- Every action of the trigger ran. Every line but two is observed when the configuration logs
  it, so a `DROPPED` for these types in `p1-defaults` means that the type is not logged.
- RegistryEvent rename (14) is not observed: the trigger renames the key with `Rename-Item`,
  which does not produce event 14. Events 12 and 13 of the same RegistryEvent filter are.
- FileDeleteDetected (26) is not observed while FileDelete (23) logs the same deletion. The
  trigger cannot show what happens to 26 alone, so its default stays unknown.
- ClipboardChange (24) is observed with `<CaptureClipboard/>`. `p1-defaults` has no such option,
  so its result for 24 says nothing about a configuration that captures the clipboard.
