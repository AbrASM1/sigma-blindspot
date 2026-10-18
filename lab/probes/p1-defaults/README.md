# P1: defaults of event types absent from the config

Question: what does Sysmon log for an event type that the configuration does not mention? Only
NetworkConnect (3) and ImageLoad (7) are documented ("disabled by default"). sigma-blindspot
reports every other type as `UNKNOWN` until this probe answers.

The configuration has an empty `<EventFiltering>`. The trigger performs one benign action per
event type and cleans up after itself (files under `%TEMP%`, keys under
`HKCU\Software\SigmaBlindspotProbe`):

| Line | Event type | Action |
| --- | --- | --- |
| 1 | ProcessCreate (1) | a copy of `cmd.exe` runs `rem` |
| 2 | FileCreateTime (2) | the creation time of a new file is set back one day |
| 3 | NetworkConnect (3) | TCP connection to `example.org:80` |
| 4 | ProcessTerminate (5) | the `cmd.exe` copy of line 1 exits |
| 5 | ImageLoad (7) | a copy of `version.dll` is loaded and freed |
| 6 | ProcessAccess (10) | a handle is opened on a child `cmd.exe` copy running `ping` |
| 7 | FileCreate (11) | a text file is written |
| 8 to 10 | RegistryEvent (12, 13, 14) | a key is created, a value set, the key renamed |
| 11 | FileCreateStreamHash (15) | an alternate data stream is written |
| 12, 13 | PipeEvent (17, 18) | a named pipe is created and a client connects |
| 14 | DnsQuery (22) | `example.org` is resolved |
| 15, 17 | FileDelete (23), FileDeleteDetected (26) | a text file is deleted |
| 16 | ClipboardChange (24) | text is copied to the clipboard |
| 18, 19 | FileBlockExecutable (27), FileExecutableDetected (29) | `cmd.exe` is copied to `%TEMP%` |

Not triggered, because no benign action produces them: DriverLoad (6), CreateRemoteThread (8),
RawAccessRead (9), WmiEvent (19, 20, 21), ProcessTampering (25), FileBlockShredding (28). Event
IDs 4, 16 and 255 cannot be filtered.

Reading the result: `OBSERVED LOGGED` means the type is logged without a filter, `DROPPED` that
it is not. Some types also need a configuration option (ClipboardChange needs
`<CaptureClipboard/>`), so `DROPPED` for them is the default with this configuration. Record
each type in `src/sigma_blindspot/sysmon/events.py`, with the Sysmon version printed by the
probe.
