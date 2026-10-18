# P6: leading and trailing whitespace in values

Question: are spaces at the start or the end of a condition value compared literally, or does
Sysmon trim them? sigma-blindspot assumes they are compared literally.

The configuration includes command lines that `end with` the marker of line 1 followed by a
space, or that contain a space followed by the marker of line 2 or of line 3. The trigger runs
`cmd /c rem` with the marker of line 1 at the very end, with `x` glued before the marker of line
2, and with the marker of line 3 after a space.

Reading the result: line 3 must be `LOGGED` in every case, it shows the configuration works.
The assumption holds if lines 1 and 2 are `DROPPED`. If they are `LOGGED`, Sysmon trims the
values.
