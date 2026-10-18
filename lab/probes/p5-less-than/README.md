# P5: less than

Question: does `less than` compare values as numbers or as text? sigma-blindspot assumes it
compares lower-cased values as text.

The configuration includes network connections whose `DestinationPort` is `less than 100`. The
trigger connects to `example.org` on port 80 (line 1) and 443 (line 2). The probe finds the
events by the process ID of the trigger.

Reading the result: as text, `"80"` and `"443"` are both greater than `"100"`, so both lines are
`DROPPED`, which is what sigma-blindspot predicts. As numbers, line 1 is `LOGGED`. Run
`p5-more-than` too.
