# sigma-blindspot

Emulates Sysmon event filtering from a configuration file; proving which Sigma rules can never fire is not implemented yet.

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
uv run sigma-blindspot inspect CONFIG
uv run sigma-blindspot check-event CONFIG EVENTS
```

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
events.jsonl:4: EventID 22 LOGGED no filter for this event type, assumed default
4 events: 2 logged, 2 dropped
```

Exit codes: `0` success, `1` failed `doctor` check or output closed early, `2` invalid input. Encodings, implemented Sysmon semantics and known limitations: `docs/reference.md`.
