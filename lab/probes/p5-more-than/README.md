# P5: more than

Question: does `more than` compare values as numbers or as text? sigma-blindspot assumes it
compares lower-cased values as text.

The configuration includes network connections whose `DestinationPort` is `more than 5`. The
trigger connects to `example.org` on port 80 (line 1) and 443 (line 2). The probe finds the
events by the process ID of the trigger.

Reading the result: as text, `"80"` is greater than `"5"` but `"443"` is not, so line 1 is
`LOGGED` and line 2 `DROPPED`, which is what sigma-blindspot predicts. As numbers, both lines
are `LOGGED`. Run `p5-less-than` too.
