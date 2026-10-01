import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from importlib import metadata
from pathlib import Path
from types import MappingProxyType
from typing import Final

from sigma_blindspot import doctor
from sigma_blindspot.errors import SourceError
from sigma_blindspot.report.html import Evaluated, EventsInput, render
from sigma_blindspot.sysmon.events import EVENT_IDS_BY_TAG, EventTag, logged_without_filter
from sigma_blindspot.sysmon.jsonl import parse_events
from sigma_blindspot.sysmon.model import Condition, Decision, EventFilter, Rule
from sigma_blindspot.sysmon.parser import parse_config

EXIT_OK: Final = 0
EXIT_FAILURE: Final = 1
EXIT_ERROR: Final = 2
_CONTROL_ESCAPES: Final = MappingProxyType(
    {code: f"\\x{code:02x}" for code in (*range(0x20), 0x7F)}
)


def _version() -> str:
    return metadata.version("sigma-blindspot")


def _ascii(text: str) -> str:
    return text.translate(_CONTROL_ESCAPES).encode("ascii", "backslashreplace").decode("ascii")


def _out(text: str) -> None:
    print(_ascii(text))


def _err(text: str) -> None:
    print(_ascii(text), file=sys.stderr)


def _quote(text: str) -> str:
    return json.dumps(text)


def _named(name: str | None) -> str:
    return "" if name is None else f" name={_quote(name)}"


def _describe_condition(condition: Condition) -> str:
    operator = _quote(condition.operator)
    value = _quote(condition.value)
    return f"{condition.field} condition={operator} value={value}{_named(condition.name)}"


def _describe_filter(event_filter: EventFilter) -> Iterator[tuple[int, str]]:
    relation = event_filter.group_relation
    grouped = "" if relation is None else f" groupRelation={_quote(relation)}"
    yield event_filter.line, f"{event_filter.tag} onmatch={_quote(event_filter.onmatch)}{grouped}"
    for item in event_filter.items:
        match item:
            case Rule():
                yield item.line, f"  Rule groupRelation={_quote(item.relation)}{_named(item.name)}"
                for condition in item.conditions:
                    yield condition.line, f"    {_describe_condition(condition)}"
            case Condition():
                yield item.line, f"  {_describe_condition(item)}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_report(target: Path | None, inputs: Iterable[Path], report: Callable[[], str]) -> None:
    if target is None:
        return
    if target.exists() and any(target.samefile(path) for path in inputs):
        raise SourceError("refusing to overwrite an input file", None, str(target))
    target.write_bytes(report().encode("utf-8"))


def _verdict(decision: Decision, config_source: str) -> str:
    state = "LOGGED" if decision.logged else "DROPPED"
    where = ", ".join(f"{config_source}:{line}" for line in decision.lines)
    return f"{state} {decision.reason}" + (f" ({where})" if where else "")


def _doctor(_: argparse.Namespace) -> int:
    checks = doctor.run_checks()
    _out(f"sigma-blindspot {_version()}")
    for check in checks:
        status = "OK" if check.ok else f"FAIL ({check.error})"
        _out(f"{check.name} {check.version or 'missing'}: {status}")
    return EXIT_OK if all(check.ok for check in checks) else EXIT_FAILURE


def _inspect(arguments: argparse.Namespace) -> int:
    data = arguments.config.read_bytes()
    config = parse_config(data, str(arguments.config))
    _write_report(
        arguments.html, (arguments.config,), lambda: render(_version(), config, _sha256(data))
    )
    _out(f"{config.source}: schema {config.schema_version}, {len(config.filters)} filters")
    for event_filter in config.filters:
        for line, text in _describe_filter(event_filter):
            _out(f"{config.source}:{line}: {text}")
    for tag in EventTag:
        if not config.filters_for(tag):
            state = "logged" if logged_without_filter(tag) else "dropped"
            ids = ", ".join(map(str, EVENT_IDS_BY_TAG[tag]))
            _out(f"{config.source}: no filter for {tag} ({ids}), {state} by assumed default")
    return EXIT_OK


def _check_event(arguments: argparse.Namespace) -> int:
    config_data = arguments.config.read_bytes()
    config = parse_config(config_data, str(arguments.config))
    events_data = arguments.events.read_bytes()
    evaluated = tuple(
        Evaluated(line, event, config.evaluate(event))
        for line, event in parse_events(events_data, str(arguments.events))
    )
    events = EventsInput(str(arguments.events), _sha256(events_data), evaluated)
    inputs = (arguments.config, arguments.events)
    _write_report(
        arguments.html, inputs, lambda: render(_version(), config, _sha256(config_data), events)
    )
    for item in evaluated:
        verdict = _verdict(item.decision, config.source)
        _out(f"{events.source}:{item.line}: EventID {item.event.event_id} {verdict}")
    logged = sum(item.decision.logged for item in evaluated)
    _out(f"{len(evaluated)} events: {logged} logged, {len(evaluated) - logged} dropped")
    return EXIT_OK


_COMMANDS: Final[Mapping[str, Callable[[argparse.Namespace], int]]] = MappingProxyType(
    {"doctor": _doctor, "inspect": _inspect, "check-event": _check_event}
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigma-blindspot",
        description="Prove which Sigma rules can never fire under a Sysmon configuration.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    commands.add_parser("doctor", help="check that the runtime dependencies work")
    inspect = commands.add_parser("inspect", help="show the filters parsed from a Sysmon config")
    inspect.add_argument("config", type=Path, metavar="CONFIG")
    check = commands.add_parser("check-event", help="emulate Sysmon filtering on exported events")
    check.add_argument("config", type=Path, metavar="CONFIG")
    check.add_argument("events", type=Path, metavar="EVENTS", help="JSON Lines event export")
    for command in (inspect, check):
        command.add_argument(
            "--html", type=Path, metavar="FILE", help="also write an HTML report to FILE"
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        code = _COMMANDS[arguments.command](arguments)
        sys.stdout.flush()
        return code
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_FAILURE
    except SourceError as error:
        _err(f"error: {error}")
    except OSError as error:
        _err(f"error: {error}")
    return EXIT_ERROR
