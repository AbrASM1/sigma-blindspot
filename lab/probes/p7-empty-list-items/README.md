# P7: empty items in a `;` list

Question: are empty items of a `;` list ignored? sigma-blindspot assumes they are. If an empty
item matched as an empty string, `contains any` would match every event.

The configuration includes command lines that contain any of `;MARKER-1;;MARKER-2;`, a list
with empty items at both ends and in the middle. The trigger runs `cmd /c rem` with the markers
of lines 1, 2 and 3.

Reading the result: the assumption holds if lines 1 and 2 are `LOGGED` and line 3 `DROPPED`.
Line 3 `LOGGED` means an empty item matches everything.
