import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from importlib import metadata
from pathlib import Path
from types import MappingProxyType
from typing import Final, NoReturn, TextIO

from sigma_blindspot import doctor, help_text
from sigma_blindspot.console import ColorMode, color_enabled, paint, paint_counts
from sigma_blindspot.errors import ConfigError, SourceError
from sigma_blindspot.prover.prove import DEFAULT_TIMEOUT_MS, RETRY_FACTOR, Verdict
from sigma_blindspot.report.analysis import (
    ORDER,
    Analysis,
    counted,
    failing,
    json_document,
    result_lines,
    summary_line,
)
from sigma_blindspot.report.html import Evaluated, EventsInput, render
from sigma_blindspot.report.markdown import markdown_lines
from sigma_blindspot.report.navigator import layer_document
from sigma_blindspot.report.sarif import sarif_document
from sigma_blindspot.runner import (
    DEFAULT_JOBS,
    RULES_PER_WORKER,
    auto_jobs,
    default_jobs,
    prove_all,
)
from sigma_blindspot.samples import NO_REGRESSION_DATA, check_samples, load_samples
from sigma_blindspot.sigma.ir import LoadedRule, Skipped
from sigma_blindspot.sigma.loader import load_rules
from sigma_blindspot.sysmon.events import EVENT_IDS_BY_TAG, EventTag, default_without_filter
from sigma_blindspot.sysmon.jsonl import parse_events
from sigma_blindspot.sysmon.model import Condition, EventFilter, Lines, Rule
from sigma_blindspot.sysmon.parser import parse_config

EXIT_OK: Final = 0
EXIT_FAILURE: Final = 1
EXIT_ERROR: Final = 2
_CONTROL_ESCAPES: Final = MappingProxyType(
    {code: f"\\x{code:02x}" for code in (*range(0x20), 0x7F)}
)
_STATES: Final[Mapping[bool | None, str]] = MappingProxyType(
    {True: "LOGGED", False: "DROPPED", None: "UNKNOWN"}
)
_REPORTS: Final[Mapping[str, Callable[[Analysis], Iterable[str]]]] = MappingProxyType(
    {
        "json": lambda analysis: json_document(analysis).splitlines(),
        "markdown": markdown_lines,
        "sarif": lambda analysis: sarif_document(analysis).splitlines(),
    }
)
_FORMATS: Final = ("text", *_REPORTS)
_VERDICTS: Final = tuple(map(str, ORDER))
_COMMAND_NAMES: Final = ("doctor", "inspect", "check-event", "analyze")
_AUTO: Final = "auto"
_HELP_HINT: Final = "run 'sigma-blindspot {command} --help' for the expected arguments and examples"


def _version() -> str:
    return metadata.version("sigma-blindspot")


def _ascii(text: str) -> str:
    return text.translate(_CONTROL_ESCAPES).encode("ascii", "backslashreplace").decode("ascii")


def _print(line: str) -> None:
    print(line)


def _out(text: str) -> None:
    _print(_ascii(text))


def _err(text: str) -> None:
    print(_ascii(text), file=sys.stderr)


def _status(before: str, word: str, after: str, colors: bool) -> None:
    _print(_ascii(before) + paint(word, colors) + _ascii(after))


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


def _where(config_source: str, lines: Lines) -> str:
    places = ", ".join(f"{config_source}:{line}" for line in lines)
    return f" ({places})" if places else ""


class _Progress:
    def __init__(self, total: int, stream: TextIO) -> None:
        self._total = total
        self._stream = stream
        self._step = max(1, total // 100)

    def update(self, done: int) -> None:
        if done == self._total or done % self._step == 0:
            self._stream.write(f"\rproving rules {done}/{self._total}")
            self._stream.flush()

    def clear(self) -> None:
        width = len(f"proving rules {self._total}/{self._total}")
        self._stream.write("\r" + " " * width + "\r")
        self._stream.flush()


def _progress(total: int) -> _Progress | None:
    stream = sys.stderr
    return _Progress(total, stream) if total > 1 and stream.isatty() else None


def _doctor(arguments: argparse.Namespace) -> int:
    checks = doctor.run_checks()
    _out(f"sigma-blindspot {_version()}")
    for check in checks:
        before = f"{check.name} {check.version or 'missing'}: "
        if check.ok:
            _status(before, "OK", "", arguments.colors)
        else:
            _status(before, "FAIL", f" ({check.error})", arguments.colors)
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
            ids = ", ".join(map(str, EVENT_IDS_BY_TAG[tag]))
            before = f"{config.source}: no filter for {tag} ({ids}), default: "
            _status(before, default_without_filter(tag), "", arguments.colors)
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
        decision = item.decision
        before = f"{events.source}:{item.line}: EventID {item.event.event_id} "
        after = f" {decision.reason}{_where(config.source, decision.lines)}"
        _status(before, _STATES[decision.logged], after, arguments.colors)
    counts = Counter(item.decision.logged for item in evaluated)
    summary = (
        f"{counted(len(evaluated), 'event')}: {counts[True]} logged, {counts[False]} dropped, "
        f"{counts[None]} unknown"
    )
    _print(paint_counts(_ascii(summary), arguments.colors))
    return EXIT_OK


def _report_lines(analysis: Analysis, arguments: argparse.Namespace) -> list[str]:
    if arguments.format == "text":
        return [*result_lines(analysis, arguments.only), summary_line(analysis)]
    return list(_REPORTS[arguments.format](analysis))


def _analyze(arguments: argparse.Namespace) -> int:
    data = arguments.config.read_bytes()
    config = parse_config(data, str(arguments.config))
    loaded = load_rules(arguments.rules)
    if not loaded:
        paths = ", ".join(map(str, arguments.rules))
        _err(f"warning: no Sigma rule file (*.yml) in {paths}")
    if Verdict.MISSED in arguments.only and arguments.samples is None:
        _err("warning: MISSED needs --samples DIR; without it no rule is MISSED")
    rules = [item for item in loaded if isinstance(item, LoadedRule)]
    samples = None if arguments.samples is None else load_samples(arguments.samples)
    jobs = _job_count(arguments.jobs, len(rules))
    progress = _progress(len(rules))
    try:
        update = None if progress is None else progress.update
        proofs = prove_all(config, data, rules, arguments.timeout_ms, jobs, progress=update)
    finally:
        if progress is not None:
            progress.clear()
    if samples is not None:
        proofs = check_samples(config, proofs, samples)
    skipped = (item for item in loaded if isinstance(item, Skipped))
    source = None if arguments.samples is None else str(arguments.samples)
    analysis = Analysis(_version(), config.source, _sha256(data), (*proofs, *skipped), source)
    inputs = (arguments.config, *(Path(item.source) for item in loaded))
    _write_report(arguments.navigator, inputs, lambda: layer_document(analysis))
    summary = paint_counts(_ascii(summary_line(analysis)), arguments.colors)
    if arguments.output is not None:
        lines = _report_lines(analysis, arguments)
        _write_report(arguments.output, inputs, lambda: "".join(f"{_ascii(x)}\n" for x in lines))
        _print(summary)
        _out(f"report written to {arguments.output}")
    elif arguments.format == "text":
        for line in result_lines(analysis, arguments.only):
            verdict, space, rest = line.partition(" ")
            _print(paint(verdict, arguments.colors) + space + _ascii(rest))
        _print(summary)
    else:
        for line in _report_lines(analysis, arguments):
            _out(line)
    blind = bool(failing(analysis.results))
    return EXIT_FAILURE if arguments.fail_on_blind and blind else EXIT_OK


_COMMANDS: Final[Mapping[str, Callable[[argparse.Namespace], int]]] = MappingProxyType(
    {"doctor": _doctor, "inspect": _inspect, "check-event": _check_event, "analyze": _analyze}
)


class _Formatter(argparse.RawDescriptionHelpFormatter):
    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=30)

    def _format_action(self, action: argparse.Action) -> str:
        text = super()._format_action(action)
        if isinstance(action, argparse._SubParsersAction):
            commands = text.split("\n", 1)[1]
            return "\n".join(line.removeprefix("  ") for line in commands.split("\n"))
        return text


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        _err(f"error: {message}")
        _err(f"hint: run '{self.prog} --help' for the options and examples")
        raise SystemExit(EXIT_ERROR)


def _positive(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {value}")
    return value


def _jobs(text: str) -> int | str:
    if text.strip().lower() == _AUTO:
        return _AUTO
    try:
        return _positive(text)
    except argparse.ArgumentTypeError as error:
        raise argparse.ArgumentTypeError(f"{error}, or auto") from None


def _job_count(requested: int | str | None, rules: int) -> int:
    if requested == _AUTO:
        return auto_jobs(rules, os.cpu_count())
    if isinstance(requested, int):
        return requested
    return default_jobs(rules, os.cpu_count())


def _verdicts(text: str) -> frozenset[str]:
    names = {name.strip().upper() for name in text.split(",") if name.strip()}
    unknown = sorted(names - set(_VERDICTS))
    if unknown or not names:
        found = ", ".join(unknown) or repr(text)
        raise argparse.ArgumentTypeError(
            f"unknown verdict {found}; choose among {', '.join(_VERDICTS)}"
        )
    return frozenset(names)


def _common() -> _Parser:
    common = _Parser(add_help=False)
    common.add_argument(
        "--color",
        choices=tuple(ColorMode),
        default=ColorMode.AUTO,
        metavar="WHEN",
        help="color the verdicts: auto (in a terminal, unless NO_COLOR is set), always or "
        "never (default: auto)",
    )
    return common


def _add_analyze(commands: "argparse._SubParsersAction[_Parser]") -> _Parser:
    analyze = commands.add_parser(
        "analyze",
        help="prove which Sigma rules can never fire",
        description=help_text.ANALYZE,
        epilog=help_text.ANALYZE_EPILOG,
        formatter_class=_Formatter,
        parents=[_common()],
    )
    inputs = analyze.add_argument_group("inputs")
    inputs.add_argument(
        "config", type=Path, metavar="CONFIG", help="Sysmon XML configuration (sysmonconfig.xml)"
    )
    inputs.add_argument(
        "rules",
        type=Path,
        nargs="+",
        metavar="RULES",
        help="Sigma rule files (.yml) or folders, searched recursively",
    )
    inputs.add_argument(
        "--samples",
        type=Path,
        metavar="DIR",
        help="clone of SigmaHQ: rules whose recorded attack is dropped become MISSED",
    )
    output = analyze.add_argument_group("output")
    output.add_argument(
        "--format",
        choices=_FORMATS,
        default="text",
        help="text: one line per rule and a summary; json, markdown or sarif: a report "
        "(default: text)",
    )
    output.add_argument(
        "--only",
        type=_verdicts,
        default=frozenset(),
        metavar="VERDICTS",
        help="list only these verdicts, comma separated, for example BLIND,PARTIAL; the "
        "summary still counts every rule (text format only)",
    )
    output.add_argument(
        "--output",
        type=Path,
        metavar="FILE",
        help="write the report to FILE in UTF-8 and show only the summary",
    )
    output.add_argument(
        "--navigator",
        type=Path,
        metavar="FILE",
        help="also write an ATT&CK Navigator layer of the techniques whose rules are all "
        "BLIND to FILE",
    )
    output.add_argument(
        "--fail-on-blind",
        action="store_true",
        help="exit with 1 if a rule is BLIND, MISSED or PARTIAL",
    )
    performance = analyze.add_argument_group("performance")
    performance.add_argument(
        "--jobs",
        type=_jobs,
        default=None,
        metavar="N",
        help=f"worker processes, or auto: one per {RULES_PER_WORKER} rules, up to the number "
        f"of processors ({os.cpu_count() or 1} here) (default: {DEFAULT_JOBS}, or 1 for fewer "
        f"than {2 * RULES_PER_WORKER} rules)",
    )
    performance.add_argument(
        "--timeout-ms",
        type=_positive,
        default=DEFAULT_TIMEOUT_MS,
        metavar="N",
        help=f"Z3 time limit per check, in milliseconds; a rule that times out is proved again "
        f"once with {RETRY_FACTOR} times the limit, then gives UNKNOWN "
        f"(default: {DEFAULT_TIMEOUT_MS})",
    )
    return analyze


def _parser() -> tuple[_Parser, dict[str, _Parser]]:
    parser = _Parser(
        prog=help_text.PROGRAM,
        description=help_text.DESCRIPTION,
        epilog=help_text.EPILOG,
        formatter_class=_Formatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", title="commands")
    doctor_command = commands.add_parser(
        "doctor",
        help="check that the runtime dependencies work",
        description=help_text.DOCTOR,
        epilog=help_text.DOCTOR_EPILOG,
        formatter_class=_Formatter,
        parents=[_common()],
    )
    inspect = commands.add_parser(
        "inspect",
        help="show the filters parsed from a Sysmon configuration",
        description=help_text.INSPECT,
        epilog=help_text.INSPECT_EPILOG,
        formatter_class=_Formatter,
        parents=[_common()],
    )
    inspect.add_argument(
        "config", type=Path, metavar="CONFIG", help="Sysmon XML configuration (sysmonconfig.xml)"
    )
    check = commands.add_parser(
        "check-event",
        help="replay exported events through a Sysmon configuration",
        description=help_text.CHECK_EVENT,
        epilog=help_text.CHECK_EVENT_EPILOG,
        formatter_class=_Formatter,
        parents=[_common()],
    )
    check.add_argument(
        "config", type=Path, metavar="CONFIG", help="Sysmon XML configuration (sysmonconfig.xml)"
    )
    check.add_argument(
        "events", type=Path, metavar="EVENTS", help="JSON Lines file of events, see below"
    )
    for command in (inspect, check):
        command.add_argument(
            "--html", type=Path, metavar="FILE", help="also write a self-contained HTML report"
        )
    analyze = _add_analyze(commands)
    helper = commands.add_parser(
        "help",
        help="show the help of a command",
        description=help_text.HELP,
        formatter_class=_Formatter,
    )
    helper.add_argument("topic", nargs="?", choices=_COMMAND_NAMES, metavar="COMMAND")
    named = {"doctor": doctor_command, "inspect": inspect, "check-event": check}
    return parser, {**named, "analyze": analyze}


def _show_help(parser: argparse.ArgumentParser) -> None:
    for line in parser.format_help().splitlines():
        _out(line)


def _os_error(error: OSError, command: str) -> tuple[str, str | None]:
    if error.filename is None:
        return f"error: {error.strerror or error}", None
    path = Path(os.fsdecode(error.filename))
    if isinstance(error, FileNotFoundError):
        hint = "check the path; put a path that contains spaces in quotes"
        return f"error: {path}: file or folder not found", hint
    if path.is_dir():
        return f"error: {path}: this is a folder, a file is expected", _HELP_HINT.format(
            command=command
        )
    return f"error: {path}: {error.strerror or error}", None


def _source_hint(error: SourceError) -> str | None:
    if isinstance(error, ConfigError) and not error.source.lower().endswith(".xml"):
        return "CONFIG must be a Sysmon XML configuration, such as sysmonconfig.xml"
    if error.message == NO_REGRESSION_DATA:
        return "--samples expects a clone of SigmaHQ: the folder that contains regression_data"
    return None


def main(argv: Sequence[str] | None = None) -> int:
    parser, commands = _parser()
    arguments = parser.parse_args(argv)
    if arguments.command is None:
        _show_help(parser)
        return EXIT_ERROR
    if arguments.command == "help":
        _show_help(parser if arguments.topic is None else commands[arguments.topic])
        return EXIT_OK
    if arguments.command == "analyze" and arguments.only and arguments.format != "text":
        commands["analyze"].error("--only works with --format text")
    arguments.colors = color_enabled(ColorMode(arguments.color), sys.stdout, os.environ)
    hint: str | None = None
    try:
        code = _COMMANDS[arguments.command](arguments)
        sys.stdout.flush()
        return code
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_FAILURE
    except SourceError as error:
        _err(f"error: {error}")
        hint = _source_hint(error)
    except OSError as error:
        message, hint = _os_error(error, arguments.command)
        _err(message)
    if hint is not None:
        _err(f"hint: {hint}")
    return EXIT_ERROR
