# P2: condition names in another case

Question: does `sysmon -c` accept `condition="Contains"`, and does it then behave like
`contains`? sigma-blindspot assumes condition names ignore ASCII case (sysmon-modular relies on
it in one module).

The configuration includes process creations whose command line `Contains` the marker of line
1. The trigger runs `cmd /c rem` twice, with the markers of lines 1 and 2.

Reading the result: if `sysmon -c` rejects the configuration, the probe says so and the
assumption is wrong: the parser must reject `Contains` again. Otherwise line 1 must be `LOGGED`
and line 2 `DROPPED` for the assumption to hold.
