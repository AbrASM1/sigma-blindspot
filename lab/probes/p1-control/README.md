# P1 control: is each P1 action observed when its type is logged?

Question: P1 found most event types `DROPPED` without a filter. Was the event type off, or did
the trigger not produce the event (or the export not find it)? This probe runs the same trigger
as `p1-defaults` with a configuration that logs every action of the trigger: an `include` on the
marker (or on `example.org` and port 80) for each type, `<CaptureClipboard/>` and an empty
`exclude` for ClipboardChange. FileBlockExecutable (27) and FileBlockShredding (28) are left out:
a block filter on the marker would stop the trigger itself.

Expected lines are those of `p1-defaults` without FileBlockExecutable (27). The emulator predicts
`LOGGED` for every line.

Reading the result, line by line, with the P1 result of the same event type:

- control `LOGGED`, P1 `DROPPED`: the type is not logged without a filter (verified).
- control `LOGGED`, P1 `LOGGED`: the type is logged without a filter (verified).
- control `DROPPED`: the trigger does not produce an observable event; the P1 result for that
  type says nothing and the default stays unknown.

The `trigger:` lines at the end of the result say which actions of the trigger failed. Run
`p1-defaults` again right after this probe, on the same Sysmon version, so both results come from
the same trigger.
