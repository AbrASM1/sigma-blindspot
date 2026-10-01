import json

import pytest
from conftest import Writer
from hypothesis import given
from hypothesis import strategies as st
from strategies import encode, encodings

from sigma_blindspot.errors import EventError
from sigma_blindspot.sysmon.events import EVENT_IDS
from sigma_blindspot.sysmon.jsonl import load_events, parse_events
from sigma_blindspot.sysmon.model import Event

SOURCE = "events.jsonl"

exported_events = st.builds(
    Event,
    event_id=st.sampled_from(sorted(EVENT_IDS)),
    fields=st.dictionaries(
        st.text(min_size=1, max_size=8).filter(lambda key: key != "EventID"),
        st.text(max_size=8),
        max_size=4,
    ),
)


def export(event: Event, ascii_only: bool) -> str:
    return json.dumps({"EventID": event.event_id, **event.fields}, ensure_ascii=ascii_only)


@given(
    found=st.lists(exported_events, max_size=5),
    encoding=encodings,
    ascii_only=st.booleans(),
    newline=st.sampled_from(["\n", "\r\n"]),
)
def test_reads_back_exported_events(
    found: list[Event], encoding: str, ascii_only: bool, newline: str
) -> None:
    text = "".join(export(event, ascii_only) + newline for event in found)
    parsed = parse_events(encode(text, encoding), SOURCE)
    assert parsed == tuple(enumerate(found, start=1))


def test_skips_blank_lines_and_keeps_line_numbers() -> None:
    text = '\n  \n{"EventID": 1, "Image": "C:\\\\cmd.exe"}\n\t\n{"EventID": 4}\n'
    assert parse_events(text.encode(), SOURCE) == (
        (3, Event(1, {"Image": "C:\\cmd.exe"})),
        (5, Event(4, {})),
    )


def test_only_line_feeds_separate_events() -> None:
    value = "a b c\u0085d"
    text = json.dumps({"EventID": 1, "CommandLine": value}, ensure_ascii=False) + "\r\n"
    assert parse_events(text.encode(), SOURCE) == ((1, Event(1, {"CommandLine": value})),)


def test_load_events_reads_a_file(write: Writer) -> None:
    path = write("events.jsonl", '{"EventID": 11, "TargetFilename": "a"}\n')
    assert load_events(path) == ((1, Event(11, {"TargetFilename": "a"})),)


@pytest.mark.parametrize(
    ("line", "message"),
    [
        pytest.param('{"EventID": 1,', "invalid JSON", id="truncated"),
        pytest.param(
            '{"EventID": 1, "Image": "a", "Image": "b"}', "duplicate key 'Image'", id="dup"
        ),
        pytest.param("[" * 100_000 + "]" * 100_000, "invalid JSON", id="too-deep"),
        pytest.param('["EventID", 1]', "expected a JSON object", id="not-an-object"),
        pytest.param('{"Image": "a"}', "EventID must be an integer, got None", id="no-event-id"),
        pytest.param('{"EventID": "1"}', "EventID must be an integer, got '1'", id="string-id"),
        pytest.param('{"EventID": true}', "EventID must be an integer, got True", id="bool-id"),
        pytest.param('{"EventID": 30}', "unknown Sysmon event ID 30", id="unknown-id"),
        pytest.param('{"EventID": 1, "ProcessId": 42}', "field 'ProcessId' must be", id="number"),
        pytest.param('{"EventID": 1, "Hashes": null}', "field 'Hashes' must be", id="null"),
    ],
)
def test_rejects_invalid_events_with_their_line(line: str, message: str) -> None:
    with pytest.raises(EventError) as caught:
        parse_events(f'{{"EventID": 5}}\n{line}\n'.encode(), SOURCE)
    assert (caught.value.source, caught.value.line) == (SOURCE, 2)
    assert message in caught.value.message


def test_rejects_undecodable_bytes_with_their_line() -> None:
    with pytest.raises(EventError) as caught:
        parse_events(b'{"EventID": 4}\n{"EventID": 1, "Image": "\xff"}\n', SOURCE)
    assert (caught.value.line, caught.value.message) == (2, "not valid utf-8: invalid start byte")
