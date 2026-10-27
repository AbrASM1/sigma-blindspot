# Benchmark

sigma-blindspot 0.3.0, pysigma 1.5.1, z3-solver 5.1.0.0, Python 3.12.15 on Windows-11-10.0.26200-SP0, 4 worker processes, 2000 ms per Z3 check.

Rules: SigmaHQ `rules/windows` at commit `b7920ed31356fb7f6a9275b34737d8604c65bac3`. Configurations:

- `swiftonsecurity`: https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/1836897f12fbd6a0a473665ef6abc34a6b497e31/sysmonconfig-export.xml (SHA-256 `055febc600e6d7448cdf3812307275912927a62b1f94d0d933b64b294bc87162`)
- `neo23x0`: https://raw.githubusercontent.com/Neo23x0/sysmon-config/cfe23bfa6197adfb0c76a4a644fab2f82a5f562f/sysmonconfig-export.xml (SHA-256 `4e93c0667a95f696700c9ff266cb7dd1310861c82133e1056737b9d1ca8d3f1c`)
- `neo23x0-block`: https://raw.githubusercontent.com/Neo23x0/sysmon-config/cfe23bfa6197adfb0c76a4a644fab2f82a5f562f/sysmonconfig-export-block.xml (SHA-256 `9c4719f15aabee3f36cc624c11ff2fb55738436a30b1ec1990f7e366c8f73354`)
- `sysmon-modular`: https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43/sysmonconfig.xml (SHA-256 `64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e`)
- `sysmon-modular-excludes-only`: https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43/sysmonconfig-excludes-only.xml (SHA-256 `4c7d27bc2847f7de816ddde90e7de37d5b9473461b27424882e9b93f00cd28a4`)

Method: `analyze` on every configuration with the same rules. A `BLIND` rule can
never fire because of what the configuration does not log. For an include-only
configuration, that is what it accepts not to see to reduce noise, not a defect.
`UNKNOWN` covers unsupported Sigma constructs, Sysmon defaults not verified by a lab
probe, and Z3 timeouts. Every assumption is listed in `docs/reference.md`.

`BLIND` is a proof; `OK` is not a guarantee that real attacks are logged: it only
means that Z3 found one event that matches the rule and is logged. What Sysmon logs
for an event type without a filter comes from lab probes on Sysmon 15.22
(`lab/results/`) and may differ on other versions.

## swiftonsecurity

2420 rules analysed in 22 s.

| Verdict | Rules |
| --- | --- |
| BLIND | 142 |
| PARTIAL | 0 |
| RULE_UNSAT | 0 |
| UNKNOWN | 119 |
| OK | 1610 |
| SKIPPED | 549 |

Configuration lines that make the most rules `BLIND` or `PARTIAL`:

| Line | Rules | Element |
| --- | --- | --- |
| 425 | 100 | \<ImageLoad onmatch="include"\> |
| 472 | 23 | \<ProcessAccess onmatch="include"\> |
| 853 | 2 | \<PipeEvent onmatch="include"\> |
| 460 | 1 | \<RawAccessRead onmatch="include"\> |
| 738 | 1 | \<EventType condition="is"\>CreateKey\</EventType\> |
| 749 | 1 | \<TargetObject condition="contains"\>\\Control\\WMI\\Autologger\\\</TargetObject\> \<!--Windows: Remove noise from monitoring "\\Start"--\> |
| 937 | 1 | \<QueryName condition="end with"\>.microsoft.com\</QueryName\> \<!--Microsoft \| Microsoft default exclusion--\> |

Rules `BLIND` or `PARTIAL` without a configuration line, because their event type has no filter and is not logged without one: 13.

## neo23x0

2420 rules analysed in 24 s.

| Verdict | Rules |
| --- | --- |
| BLIND | 21 |
| PARTIAL | 0 |
| RULE_UNSAT | 0 |
| UNKNOWN | 129 |
| OK | 1721 |
| SKIPPED | 549 |

Configuration lines that make the most rules `BLIND` or `PARTIAL`:

| Line | Rules | Element |
| --- | --- | --- |
| 456 | 5 | \<ImageLoad onmatch="include"\> |
| 496 | 1 | \<RawAccessRead onmatch="include"\> |
| 875 | 1 | \<EventType condition="is"\>CreateKey\</EventType\> |
| 886 | 1 | \<TargetObject condition="contains"\>\\Control\\WMI\\Autologger\\\</TargetObject\> \<!--Windows: Remove noise from monitoring "\\Start"--\> |
| 1163 | 1 | \<QueryName condition="end with"\>.microsoft.com\</QueryName\> \<!--Microsoft \| Microsoft default exclusion--\> |

Rules `BLIND` or `PARTIAL` without a configuration line, because their event type has no filter and is not logged without one: 12.

## neo23x0-block

2420 rules analysed in 22 s.

| Verdict | Rules |
| --- | --- |
| BLIND | 21 |
| PARTIAL | 0 |
| RULE_UNSAT | 0 |
| UNKNOWN | 129 |
| OK | 1721 |
| SKIPPED | 549 |

Configuration lines that make the most rules `BLIND` or `PARTIAL`:

| Line | Rules | Element |
| --- | --- | --- |
| 413 | 5 | \<ImageLoad onmatch="include"\> |
| 453 | 1 | \<RawAccessRead onmatch="include"\> |
| 828 | 1 | \<EventType condition="is"\>CreateKey\</EventType\> |
| 839 | 1 | \<TargetObject condition="contains"\>\\Control\\WMI\\Autologger\\\</TargetObject\> \<!--Windows: Remove noise from monitoring "\\Start"--\> |
| 1112 | 1 | \<QueryName condition="end with"\>.microsoft.com\</QueryName\> \<!--Microsoft \| Microsoft default exclusion--\> |

Rules `BLIND` or `PARTIAL` without a configuration line, because their event type has no filter and is not logged without one: 12.

## sysmon-modular

2420 rules analysed in 50 s.

| Verdict | Rules |
| --- | --- |
| BLIND | 16 |
| PARTIAL | 1 |
| RULE_UNSAT | 0 |
| UNKNOWN | 137 |
| OK | 1717 |
| SKIPPED | 549 |

Configuration lines that make the most rules `BLIND` or `PARTIAL`:

| Line | Rules | Element |
| --- | --- | --- |
| 97 | 1 | \<GrantedAccess\>0x1400\</GrantedAccess\> |
| 808 | 1 | \<EventType condition="is"\>CreateKey\</EventType\> |
| 889 | 1 | \<TargetObject condition="contains"\>\\Control\\WMI\\Autologger\\\</TargetObject\> |
| 3098 | 1 | \<QueryName condition="end with"\>.microsoft.com\</QueryName\> |
| 4241 | 1 | \<RawAccessRead onmatch="include"\> |

Rules `BLIND` or `PARTIAL` without a configuration line, because their event type has no filter and is not logged without one: 12.

## sysmon-modular-excludes-only

2420 rules analysed in 17 s.

| Verdict | Rules |
| --- | --- |
| BLIND | 25 |
| PARTIAL | 1 |
| RULE_UNSAT | 0 |
| UNKNOWN | 128 |
| OK | 1717 |
| SKIPPED | 549 |

Configuration lines that make the most rules `BLIND` or `PARTIAL`:

| Line | Rules | Element |
| --- | --- | --- |
| 97 | 1 | \<GrantedAccess\>0x1400\</GrantedAccess\> |
| 300 | 1 | \<EventType condition="is"\>CreateKey\</EventType\> |
| 381 | 1 | \<TargetObject condition="contains"\>\\Control\\WMI\\Autologger\\\</TargetObject\> |
| 1159 | 1 | \<QueryName condition="end with"\>.microsoft.com\</QueryName\> |

Rules `BLIND` or `PARTIAL` without a configuration line, because their event type has no filter and is not logged without one: 22.
