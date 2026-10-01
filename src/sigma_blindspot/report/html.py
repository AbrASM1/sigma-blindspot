import base64
import hashlib
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from html import escape
from itertools import groupby
from typing import Final

from sigma_blindspot.sysmon.events import (
    EVENT_IDS_BY_TAG,
    TAG_BY_EVENT_ID,
    EventTag,
    logged_without_filter,
)
from sigma_blindspot.sysmon.model import (
    Condition,
    Decision,
    Event,
    EventFilter,
    Reason,
    Rule,
    SysmonConfig,
)
from sigma_blindspot.sysmon.semantics import Semantic, Status

STYLE: Final = """
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #1f2328;
  --muted: #59636e;
  --border: #d1d9e0;
  --panel: #f6f8fa;
  --accent: #0969da;
  --ok: #1a7f37;
  --ok-bg: #dafbe1;
  --bad: #cf222e;
  --bad-bg: #ffebe9;
  --warn: #9a6700;
  --warn-bg: #fff8c5;
  --other: #8250df;
  --other-bg: #fbefff;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --fg: #e6edf3;
    --muted: #9198a1;
    --border: #3d444d;
    --panel: #151b23;
    --accent: #4493f8;
    --ok: #3fb950;
    --ok-bg: #12261e;
    --bad: #f85149;
    --bad-bg: #25171c;
    --warn: #d29922;
    --warn-bg: #272115;
    --other: #ab7df8;
    --other-bg: #221a33;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
header, main, footer { max-width: 1280px; margin: 0 auto; padding: 16px 24px; }
header { border-bottom: 1px solid var(--border); }
footer { border-top: 1px solid var(--border); color: var(--muted); }
h1 { margin: 0 0 12px; font-size: 20px; }
h1 small { color: var(--muted); font-size: 14px; font-weight: 400; }
h2 {
  margin: 32px 0 12px;
  padding-bottom: 4px;
  border-bottom: 1px solid var(--border);
  font-size: 16px;
}
code {
  font: 12.5px/1.4 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
  overflow-wrap: anywhere;
}
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0; }
dt { color: var(--muted); }
dd { margin: 0; }
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
  margin: 16px 0;
}
.card {
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--panel);
}
.card strong { display: block; font-size: 24px; font-weight: 600; }
.card span { color: var(--muted); }
.card.ok strong { color: var(--ok); }
.card.bad strong { color: var(--bad); }
.card.warn strong { color: var(--warn); }
table { width: 100%; border-collapse: collapse; }
th, td {
  padding: 4px 8px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}
thead th { position: sticky; top: 0; background: var(--panel); }
tbody tr:hover { background: var(--panel); }
tr:target { background: var(--warn-bg); }
tr.group th { padding-top: 16px; background: var(--bg); }
td.line { width: 1%; color: var(--muted); text-align: right; font-variant-numeric: tabular-nums; }
td.nested { padding-left: 32px; }
td.nested2 { padding-left: 56px; }
.badge {
  display: inline-block;
  padding: 0 8px;
  border: 1px solid;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
}
.badge.ok { color: var(--ok); background: var(--ok-bg); }
.badge.bad { color: var(--bad); background: var(--bad-bg); }
.badge.warn { color: var(--warn); background: var(--warn-bg); }
.badge.include { color: var(--accent); }
.badge.exclude { color: var(--other); background: var(--other-bg); }
.esc { padding: 0 2px; border-radius: 3px; color: var(--bad); background: var(--bad-bg); }
code.value:empty::after { content: "(empty)"; color: var(--muted); font-style: italic; }
details summary { cursor: pointer; }
details table { margin-top: 4px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
@media print {
  thead th { position: static; }
  a { color: inherit; }
}
"""
CONTENT_SECURITY_POLICY: Final = (
    "default-src 'none'; "
    f"style-src 'sha256-{base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()}'; "
    "base-uri 'none'; form-action 'none'"
)
_BACKTICKS: Final = re.compile(r"`([^`]+)`")
_CONFIG_HEAD: Final = (
    "<tr><th>Line</th><th>Element</th><th>Field</th><th>Condition</th><th>Value</th>"
    "<th>Name</th></tr>"
)
_EVENTS_HEAD: Final = (
    "<tr><th>Line</th><th>Event</th><th>Verdict</th><th>Reason</th><th>Config lines</th>"
    "<th>Fields</th></tr>"
)


@dataclass(frozen=True, slots=True)
class Evaluated:
    line: int
    event: Event
    decision: Decision


@dataclass(frozen=True, slots=True)
class EventsInput:
    source: str
    sha256: str
    evaluated: tuple[Evaluated, ...]


def _run(printable: bool, characters: str) -> str:
    if printable:
        return escape(characters)
    revealed = escape(characters.encode("unicode_escape").decode("ascii"))
    return f'<span class="esc">{revealed}</span>'


def _text(value: str) -> str:
    runs = groupby(value, str.isprintable)
    return "".join(_run(printable, "".join(characters)) for printable, characters in runs)


def _code(value: str, kind: str = "") -> str:
    css = f' class="{kind}"' if kind else ""
    return f"<code{css}>{_text(value)}</code>"


def _prose(text: str) -> str:
    return _BACKTICKS.sub(r"<code>\1</code>", escape(text))


def _badge(kind: str, label: str) -> str:
    return f'<span class="badge {kind}">{escape(label)}</span>'


def _card(kind: str, value: str, label: str) -> str:
    return f'<div class="card {kind}"><strong>{escape(value)}</strong><span>{label}</span></div>'


def _links(lines: Iterable[int]) -> str:
    return ", ".join(f'<a href="#L{line}">{line}</a>' for line in lines)


def _name(name: str | None) -> str:
    return "" if name is None else _code(name)


def _logged(logged: bool) -> str:
    return _badge("ok", "LOGGED") if logged else _badge("bad", "DROPPED")


def _verdict(decision: Decision) -> str:
    assumed = " " + _badge("warn", "assumed") if decision.reason is Reason.DEFAULT else ""
    return _logged(decision.logged) + assumed


def _event_type(event_id: int) -> str:
    tag = TAG_BY_EVENT_ID.get(event_id)
    return f"{tag} ({event_id})" if tag is not None else f"not filterable ({event_id})"


def _fields(event: Event) -> str:
    rows = "".join(
        f"<tr><td>{_code(name)}</td><td>{_code(value, 'value')}</td></tr>"
        for name, value in event.fields.items()
    )
    return (
        f"<details><summary>Fields ({len(event.fields)})</summary><table>{rows}</table></details>"
    )


def _condition_count(config: SysmonConfig) -> int:
    return sum(
        len(item.conditions) if isinstance(item, Rule) else 1
        for event_filter in config.filters
        for item in event_filter.items
    )


def _header(config: SysmonConfig, config_sha256: str, events: EventsInput | None) -> str:
    entries = [
        ("Configuration", f"{_code(config.source)}<br>schema {escape(config.schema_version)}"),
        ("SHA-256", _code(config_sha256)),
    ]
    if events is not None:
        entries += [("Events", _code(events.source)), ("SHA-256", _code(events.sha256))]
    terms = "".join(f"<dt>{term}</dt><dd>{value}</dd>" for term, value in entries)
    return f"<dl>{terms}</dl>"


def _summary(config: SysmonConfig, events: EventsInput | None) -> str:
    filtered = sum(1 for tag in EventTag if config.filters_for(tag))
    decisions = [item.decision for item in events.evaluated] if events is not None else []
    logged = sum(decision.logged for decision in decisions)
    assumed = sum(decision.reason is Reason.DEFAULT for decision in decisions)
    event_cards = (
        _card("", str(len(decisions)), "events"),
        _card("ok", str(logged), "logged"),
        _card("bad", str(len(decisions) - logged), "dropped"),
        _card("warn", str(assumed), "decided by assumed default"),
    )
    config_cards = (
        _card("", str(len(config.filters)), "filters"),
        _card("", str(_condition_count(config)), "conditions"),
        _card("", f"{filtered} / {len(EventTag)}", "event types filtered"),
        _card("warn", str(len(EventTag) - filtered), "event types on assumed default"),
    )
    groups = (event_cards, config_cards) if events is not None else (config_cards,)
    return "".join(f'<section class="cards">{"".join(cards)}</section>' for cards in groups)


def _events_section(events: EventsInput) -> str:
    rows = "\n".join(
        f'<tr><td class="line">{item.line}</td>'
        f"<td>{escape(_event_type(item.event.event_id))}</td>"
        f"<td>{_verdict(item.decision)}</td><td>{escape(item.decision.reason)}</td>"
        f"<td>{_links(item.decision.lines)}</td><td>{_fields(item.event)}</td></tr>"
        for item in events.evaluated
    )
    table = f"<table><thead>{_EVENTS_HEAD}</thead><tbody>\n{rows}\n</tbody></table>"
    return f"<section><h2>Events</h2>{table}</section>"


@dataclass(frozen=True, slots=True)
class _Row:
    cells: str
    line: int | None = None
    kind: str = ""


def _condition_row(condition: Condition, depth: str) -> _Row:
    cells = (
        f'<td class="line">{condition.line}</td><td class="{depth}">condition</td>'
        f"<td>{_code(condition.field)}</td><td>{_code(condition.operator)}</td>"
        f"<td>{_code(condition.value, 'value')}</td><td>{_name(condition.name)}</td>"
    )
    return _Row(cells, condition.line)


def _rule_rows(rule: Rule) -> Iterator[_Row]:
    cells = (
        f'<td class="line">{rule.line}</td><td class="nested">rule '
        f"{_badge('include', rule.relation)}</td><td></td><td></td><td></td>"
        f"<td>{_name(rule.name)}</td>"
    )
    yield _Row(cells, rule.line)
    for condition in rule.conditions:
        yield _condition_row(condition, "nested2")


def _filter_rows(event_filter: EventFilter) -> Iterator[_Row]:
    relation = event_filter.group_relation
    grouping = "no RuleGroup" if relation is None else f"RuleGroup {relation}"
    onmatch = _badge(event_filter.onmatch, event_filter.onmatch)
    cells = (
        f'<td class="line">{event_filter.line}</td>'
        f'<td colspan="5">{onmatch} filter, {escape(grouping)}</td>'
    )
    yield _Row(cells, event_filter.line)
    for item in event_filter.items:
        match item:
            case Rule():
                yield from _rule_rows(item)
            case Condition():
                yield _condition_row(item, "nested")


def _tag_rows(config: SysmonConfig, tag: EventTag) -> Iterator[_Row]:
    ids = ", ".join(map(str, EVENT_IDS_BY_TAG[tag]))
    yield _Row(f'<th colspan="6">{escape(tag)} ({ids})</th>', kind="group")
    for event_filter in config.filters_for(tag):
        yield from _filter_rows(event_filter)


def _rendered(rows: Iterable[_Row]) -> Iterator[str]:
    anchored: set[int | None] = {None}
    for row in rows:
        anchor = "" if row.line in anchored else f' id="L{row.line}"'
        anchored.add(row.line)
        kind = f' class="{row.kind}"' if row.kind else ""
        yield f"<tr{anchor}{kind}>{row.cells}</tr>"


def _config_section(config: SysmonConfig) -> str:
    if not config.filters:
        return "<section><h2>Configuration</h2><p>No event filter.</p></section>"
    tags = (tag for tag in EventTag if config.filters_for(tag))
    body = "\n".join(_rendered(row for tag in tags for row in _tag_rows(config, tag)))
    table = f"<table><thead>{_CONFIG_HEAD}</thead><tbody>\n{body}\n</tbody></table>"
    return f"<section><h2>Configuration</h2>{table}</section>"


def _defaults_section(config: SysmonConfig) -> str:
    rows = "\n".join(
        f"<tr><td>{escape(tag)}</td><td>{', '.join(map(str, EVENT_IDS_BY_TAG[tag]))}</td>"
        f"<td>{_logged(logged_without_filter(tag))} {_badge('warn', 'assumed')}</td></tr>"
        for tag in EventTag
        if not config.filters_for(tag)
    )
    head = "<tr><th>Event type</th><th>Event IDs</th><th>Default</th></tr>"
    table = f"<table><thead>{head}</thead><tbody>\n{rows}\n</tbody></table>"
    content = table if rows else "<p>Every event type has a filter.</p>"
    return f"<section><h2>Event types without filter</h2>{content}</section>"


def _assumptions_section() -> str:
    items = "\n".join(
        f"<li>{_badge('warn' if semantic.status is Status.ASSUMED else 'ok', semantic.status)} "
        f"{_prose(semantic.behaviour)}</li>"
        for semantic in Semantic
        if semantic.status is not Status.DOCUMENTED
    )
    intro = (
        "<p>These Sysmon behaviours are undocumented. Decisions that depend on them are only "
        "as reliable as the assumption until a lab probe verifies it.</p>"
    )
    return f"<section><h2>Assumptions</h2>{intro}<ul>\n{items}\n</ul></section>"


def render(
    version: str, config: SysmonConfig, config_sha256: str, events: EventsInput | None = None
) -> str:
    sections = (
        _summary(config, events),
        _events_section(events) if events is not None else "",
        _config_section(config),
        _defaults_section(config),
        _assumptions_section(),
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CONTENT_SECURITY_POLICY}">
<meta name="referrer" content="no-referrer">
<title>sigma-blindspot report</title>
<style>{STYLE}</style>
</head>
<body>
<header>
<h1>sigma-blindspot report <small>{escape(version)}</small></h1>
{_header(config, config_sha256, events)}
</header>
<main>
{"".join(sections)}
</main>
<footer>Generated by sigma-blindspot {escape(version)} from the inputs above. The emulator, not a
live Sysmon, made every decision.</footer>
</body>
</html>
"""
