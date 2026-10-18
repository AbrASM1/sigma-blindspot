# sigma-blindspot

Proves which Sigma rules can never fire under a Sysmon configuration and names the configuration lines responsible.

## Install

Requires [`uv`](https://docs.astral.sh/uv/), which fetches Python 3.12 if it is missing.

```console
git clone https://github.com/AbrASM1/sigma-blindspot.git
cd sigma-blindspot
uv sync
uv run sigma-blindspot doctor
```

## Usage

```console
uv run sigma-blindspot analyze CONFIG RULES... [--format text|json|markdown|sarif] [--navigator FILE] [--fail-on-blind] [--timeout-ms N] [--jobs N]
uv run sigma-blindspot inspect CONFIG [--html FILE]
uv run sigma-blindspot check-event CONFIG EVENTS [--html FILE]
```

`analyze` on the configuration and rules in `tests/fixtures/`:

```console
$ uv run sigma-blindspot analyze tests/fixtures/sysmon.xml tests/fixtures/rules
BLIND tests/fixtures/rules/file_vbs_dropped.yml "VBScript file written" file_event (11): every matching event is dropped by the config (tests/fixtures/sysmon.xml:17)
BLIND tests/fixtures/rules/image_load_dbghelp.yml "Debug help library loaded" image_load (7): ImageLoad (7) is not logged without a filter
BLIND tests/fixtures/rules/network_smb_outbound.yml "Outbound SMB from rundll32" network_connection (3): every matching event is dropped by the config (tests/fixtures/sysmon.xml:11)
BLIND tests/fixtures/rules/process_ccmexec_child.yml "Child process of the SCCM client" process_creation (1): every matching event is dropped by the config (tests/fixtures/sysmon.xml:7)
PARTIAL tests/fixtures/rules/process_script_hosts.yml "Script host or service host started" process_creation (1): never fires: #1 selection_svchost (tests/fixtures/sysmon.xml:6)
RULE_UNSAT tests/fixtures/rules/process_contradiction.yml "Image that is both cmd and powershell" process_creation (1): the rule contradicts itself
UNKNOWN tests/fixtures/rules/process_access_lsass.yml "Process opened LSASS" process_access (10): Sysmon default unverified (probe P1)
UNKNOWN tests/fixtures/rules/process_regex.yml "Random looking executable name" process_creation (1): unsupported: regular expression (re)
OK tests/fixtures/rules/process_encoded_powershell.yml "Encoded PowerShell command line" process_creation (1): an event can match the rule and be logged
SKIPPED tests/fixtures/rules/linux_shell.yml "Shell started on Linux": not a Sysmon log source
10 rules: 4 BLIND, 1 PARTIAL, 1 RULE_UNSAT, 2 UNKNOWN, 1 OK, 1 SKIPPED
```

`check-event` emulates the configuration on exported events.

`sysmon.xml`:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="image">svchost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <NetworkConnect onmatch="include">
      <DestinationPort>443</DestinationPort>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

`events.jsonl`, one object per line, field values as strings:

```json
{"EventID": 1, "Image": "C:\\Windows\\System32\\svchost.exe"}
{"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe"}
{"EventID": 3, "Image": "C:\\Tools\\curl.exe", "DestinationPort": "80"}
{"EventID": 22, "QueryName": "example.org"}
```

```console
$ uv run sigma-blindspot check-event sysmon.xml events.jsonl
events.jsonl:1: EventID 1 DROPPED matched an exclude filter (sysmon.xml:5)
events.jsonl:2: EventID 1 LOGGED matched no exclude filter
events.jsonl:3: EventID 3 DROPPED matched no include filter (sysmon.xml:8)
events.jsonl:4: EventID 22 UNKNOWN no filter for this event type, Sysmon default unverified
4 events: 1 logged, 2 dropped, 1 unknown
```

Exit codes: `0` success, `1` a `BLIND` or `PARTIAL` rule with `--fail-on-blind`, a failed `doctor` check or output closed early, `2` invalid input. Verdicts, encodings, implemented Sysmon semantics and known limitations: `docs/reference.md`.

Not supported yet: regular expressions, CIDR ranges and null values in Sigma rules, a check of field names against the Sysmon schema, a PyPI release.
