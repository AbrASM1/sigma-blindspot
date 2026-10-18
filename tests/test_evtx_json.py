import json

import pytest
from conftest import line_of

from sigma_blindspot.errors import EventError
from sigma_blindspot.sysmon.evtx_json import SYSMON_PROVIDER, parse_evtx_json
from sigma_blindspot.sysmon.model import Event

SOURCE = "sample.json"


def exported(event_id: object, data: object, provider: str = SYSMON_PROVIDER) -> dict[str, object]:
    system = {"Provider": {"#attributes": {"Name": provider}}, "EventID": event_id}
    return {"Event": {"System": system, "EventData": data}}


def test_reads_concatenated_documents_and_keeps_sysmon_events_only() -> None:
    documents = [
        exported(1, {"Image": "C:\\cmd.exe", "ProcessId": 42, "Hashes": None}),
        exported(4104, {"ScriptBlockText": "x"}, "Microsoft-Windows-PowerShell"),
        exported({"#text": 3, "#attributes": {"Qualifiers": ""}}, {"Initiated": True}),
    ]
    text = json.dumps(documents[0], indent=2) + "\n" + "\n".join(map(json.dumps, documents[1:]))
    assert parse_evtx_json(text.encode(), SOURCE) == (
        Event(1, {"Image": "C:\\cmd.exe", "ProcessId": "42", "Hashes": ""}),
        Event(3, {"Initiated": "true"}),
    )


def test_an_event_without_data_has_no_fields() -> None:
    assert parse_evtx_json(json.dumps(exported(4, None)).encode(), SOURCE) == (Event(4, {}),)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param('{"Event": ', "invalid JSON", id="truncated"),
        pytest.param(json.dumps(exported("1", {})), "EventID must be an integer", id="string-id"),
        pytest.param(json.dumps(exported(1, [])), "EventData must be an object", id="data-list"),
        pytest.param(json.dumps(exported(1, {"A": [1]})), "unsupported field value", id="list"),
        pytest.param(json.dumps(exported(99, {})), "unknown Sysmon event ID 99", id="unknown-id"),
    ],
)
def test_rejects_malformed_samples_with_their_line(text: str, message: str) -> None:
    with pytest.raises(EventError) as caught:
        parse_evtx_json(("\n" + text).encode(), SOURCE)
    assert (caught.value.source, caught.value.line) == (SOURCE, 2)
    assert message in caught.value.message


def test_errors_point_to_the_line_where_their_document_starts() -> None:
    first = json.dumps(exported(1, {"Image": "C:\\cmd.exe"}), indent=2)
    text = "\n".join([first, json.dumps(exported(1, {})), json.dumps(exported("2", {}))])
    with pytest.raises(EventError) as caught:
        parse_evtx_json(text.encode(), SOURCE)
    assert caught.value.line == line_of(text, '"EventID": "2"')
