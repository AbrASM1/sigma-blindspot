import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Final

from sigma_blindspot.decoding import decode_text
from sigma_blindspot.errors import EventError
from sigma_blindspot.sysmon.model import Event

SYSMON_PROVIDER: Final = "Microsoft-Windows-Sysmon"
_WHITESPACE: Final = " \t\r\n"
_DECODER: Final = json.JSONDecoder()


def _documents(text: str, source: str) -> Iterator[tuple[int, object]]:
    index = counted = 0
    line = 1
    while True:
        while index < len(text) and text[index] in _WHITESPACE:
            index += 1
        if index == len(text):
            return
        line += text.count("\n", counted, index)
        counted = index
        try:
            document, index = _DECODER.raw_decode(text, index)
        except json.JSONDecodeError as error:
            raise EventError(f"invalid JSON: {error.msg}", line, source) from error
        yield line, document


def _value(value: object) -> str:
    match value:
        case None:
            return ""
        case bool():
            return "true" if value else "false"
        case str():
            return value
        case int():
            return str(value)
        case {"#text": text}:
            return _value(text)
    raise ValueError(f"unsupported field value {value!r}")


def _member(record: object, *path: str) -> object:
    for key in path:
        if not isinstance(record, Mapping):
            return None
        record = record.get(key)
    return record


def _event(document: object) -> Event | None:
    if _member(document, "Event", "System", "Provider", "#attributes", "Name") != SYSMON_PROVIDER:
        return None
    event_id = _member(document, "Event", "System", "EventID")
    if isinstance(event_id, Mapping):
        event_id = event_id.get("#text")
    if type(event_id) is not int:
        raise ValueError(f"EventID must be an integer, got {event_id!r}")
    data = _member(document, "Event", "EventData")
    if data is None:
        return Event(event_id, {})
    if not isinstance(data, Mapping):
        raise ValueError("EventData must be an object")
    return Event(event_id, {str(name): _value(value) for name, value in data.items()})


def parse_evtx_json(data: bytes, source: str) -> tuple[Event, ...]:
    events: list[Event] = []
    for line, document in _documents(decode_text(data, source, EventError), source):
        try:
            event = _event(document)
        except ValueError as error:
            raise EventError(str(error), line, source) from error
        if event is not None:
            events.append(event)
    return tuple(events)


def load_evtx_json(path: Path) -> tuple[Event, ...]:
    return parse_evtx_json(path.read_bytes(), str(path))
