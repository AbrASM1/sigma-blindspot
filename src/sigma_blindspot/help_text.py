from typing import Final

PROGRAM: Final = "sigma-blindspot"

DESCRIPTION: Final = """\
Prove which Sigma rules can never fire under a Sysmon configuration, and name the
configuration lines responsible."""

EPILOG: Final = """\
Getting started (PowerShell):
  sigma-blindspot doctor
      check that Python, pySigma and Z3 work
  sigma-blindspot inspect .\\sysmonconfig.xml
      list the filters of a Sysmon configuration, with their line numbers
  sigma-blindspot analyze .\\sysmonconfig.xml .\\sigma\\rules\\windows
      prove which Sigma rules can never fire under that configuration
  sigma-blindspot check-event .\\sysmonconfig.xml .\\events.jsonl
      replay exported events through the configuration: logged or dropped

Run 'sigma-blindspot help COMMAND' or 'sigma-blindspot COMMAND --help' for the
options and more examples of a command.
Documentation: https://github.com/AbrASM1/sigma-blindspot"""

DOCTOR: Final = "Check that the runtime dependencies (pySigma and Z3) are installed and work."

DOCTOR_EPILOG: Final = """\
Example (PowerShell):
  sigma-blindspot doctor

Exit codes: 0 every check passed, 1 a check failed."""

INSPECT: Final = """\
Show the filters that sigma-blindspot reads from a Sysmon configuration, each with
its line number, and what Sysmon does with the event types that have no filter."""

INSPECT_EPILOG: Final = """\
Examples (PowerShell):
  # every filter and condition, with its line in the file
  sigma-blindspot inspect .\\sysmonconfig.xml

  # the same, as a self-contained HTML page
  sigma-blindspot inspect .\\sysmonconfig.xml --html .\\config.html

Exit codes: 0 success, 2 invalid input (missing file or invalid configuration)."""

CHECK_EVENT: Final = """\
Replay events through a Sysmon configuration and say, for each one, whether Sysmon
logs it (LOGGED), drops it (DROPPED) or whether that is not known (UNKNOWN), with the
configuration lines that decide."""

CHECK_EVENT_EPILOG: Final = """\
EVENTS is a JSON Lines file: one JSON object per line, with the EventID and the
fields of the event as strings, for example
  {"EventID": 1, "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe"}
lab\\Export-SysmonEvents.ps1 exports real Sysmon events in this format.

Examples (PowerShell):
  # write one event, then check it
  '{"EventID": 1, "Image": "C:\\\\Tools\\\\nc.exe"}' | Set-Content -Encoding utf8 .\\events.jsonl
  sigma-blindspot check-event .\\sysmonconfig.xml .\\events.jsonl

  # the same, with an HTML page linking each verdict to the configuration
  sigma-blindspot check-event .\\sysmonconfig.xml .\\events.jsonl --html .\\events.html

Exit codes: 0 success, 2 invalid input (missing file, invalid configuration or events)."""

ANALYZE: Final = """\
Prove, for each Sigma rule, whether an event that matches it can be logged under a
Sysmon configuration. Rules that can never fire are reported with the configuration
lines responsible."""

ANALYZE_EPILOG: Final = """\
Examples (PowerShell):
  # every rule, one line each, then a summary
  sigma-blindspot analyze .\\sysmonconfig.xml .\\sigma\\rules\\windows

  # only the rules that can never fire, in full or in part
  sigma-blindspot analyze .\\sysmonconfig.xml .\\sigma\\rules\\windows --only BLIND,PARTIAL

  # also check SigmaHQ's recorded attacks (.\\sigma is a clone of SigmaHQ)
  sigma-blindspot analyze .\\sysmonconfig.xml .\\sigma\\rules\\windows --samples .\\sigma

  # a Markdown report grouped by configuration line, saved as UTF-8
  sigma-blindspot analyze .\\sysmonconfig.xml .\\rules --format markdown --output .\\report.md

  # in a CI job: fail when a rule cannot fire
  sigma-blindspot analyze .\\sysmonconfig.xml .\\rules --fail-on-blind --color never

Verdicts:
  BLIND       proved: no event that matches the rule can be logged
  MISSED      with --samples: SigmaHQ's recorded attack is dropped by the configuration
  PARTIAL     some branches of the rule can never fire, the others can
  RULE_UNSAT  the rule contradicts itself, whatever the configuration
  UNKNOWN     not decided: unsupported Sigma construct, unverified Sysmon default
              or Z3 timeout; the reason says which
  OK          not provably blind; not a guarantee that real attacks are logged
  SKIPPED     not a Sysmon rule, or the file could not be loaded

Exit codes:
  0  the analysis ran
  1  --fail-on-blind and at least one rule is BLIND, MISSED or PARTIAL
  2  invalid input: missing file, invalid configuration or invalid samples"""

HELP: Final = "Show the help of a command, with its options and examples."
