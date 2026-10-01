import codecs
import json
from collections import Counter
from pathlib import Path
from typing import Final

from sigma_blindspot.errors import EventError
from sigma_blindspot.sysmon.model import Event

EVENT_ID_KEY: Final = "EventID"
_JSON_WHITESPACE: Final = " \t\r\n"
_BOM_ENCODINGS: Final = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)

type NumberedEvent = tuple[int, Event]


def _decode(data: bytes, source: str) -> str:
    encoding = next((name for bom, name in _BOM_ENCODINGS if data.startswith(bom)), "utf-8")
    try:
        return data.decode(encoding)
    except UnicodeDecodeError as error:
        message = f"not valid {encoding}: {error.reason} at byte {error.start}"
        raise EventError(message, None, source) from error


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    counts = Counter(key for key, _ in pairs)
    duplicate = next((key for key, count in counts.items() if count > 1), None)
    if duplicate is not None:
        raise ValueError(f"duplicate key {duplicate!r}")
    return dict(pairs)


def _parse_event(line: str, number: int, source: str) -> Event:
    def error(message: str) -> EventError:
        return EventError(message, number, source)

    try:
        record = json.loads(line, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as cause:
        raise error(f"invalid JSON: {cause}") from cause
    if not isinstance(record, dict):
        raise error("expected a JSON object")
    event_id = record.get(EVENT_ID_KEY)
    if type(event_id) is not int:
        raise error(f"{EVENT_ID_KEY} must be an integer, got {event_id!r}")
    fields = {key: value for key, value in record.items() if key != EVENT_ID_KEY}
    invalid = next((key for key, value in fields.items() if not isinstance(value, str)), None)
    if invalid is not None:
        raise error(f"field {invalid!r} must be a string")
    try:
        return Event(event_id, fields)
    except ValueError as cause:
        raise error(str(cause)) from cause


def parse_events(data: bytes, source: str) -> tuple[NumberedEvent, ...]:
    lines = _decode(data, source).split("\n")
    return tuple(
        (number, _parse_event(line, number, source))
        for number, line in enumerate(lines, start=1)
        if line.strip(_JSON_WHITESPACE)
    )


def load_events(path: Path) -> tuple[NumberedEvent, ...]:
    return parse_events(path.read_bytes(), str(path))
