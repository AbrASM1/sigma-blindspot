import base64
import hashlib
import re
from html.parser import HTMLParser

from conftest import DOC_SAMPLE
from hypothesis import given
from hypothesis import strategies as st
from strategies import SOURCE, config_of, encodings, render, xml_documents

from sigma_blindspot.report.html import CONTENT_SECURITY_POLICY, Evaluated, EventsInput
from sigma_blindspot.report.html import render as render_report
from sigma_blindspot.sysmon.events import EVENT_IDS, EventTag
from sigma_blindspot.sysmon.model import Event, EventFilter, Rule, SysmonConfig
from sigma_blindspot.sysmon.parser import parse_config

ALLOWED_TAGS = frozenset(
    "html head meta title style body header h1 small dl dt dd br code main section div strong "
    "span h2 p table thead tbody tr th td a details summary ul li footer".split()
)
ALLOWED_ATTRIBUTES = frozenset(
    {"lang", "charset", "name", "content", "http-equiv", "class", "id", "href", "colspan"}
)
DIGEST = "0" * 64

any_events = st.builds(
    Event,
    event_id=st.sampled_from(sorted(EVENT_IDS)),
    fields=st.dictionaries(st.text(max_size=6), st.text(max_size=12), max_size=3),
)


class Page(HTMLParser):
    def __init__(self, document: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str]] = []
        self.styles: list[str] = []
        self.text: list[str] = []
        self.in_style = False
        self.feed(document)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend((name, value or "") for name, value in attrs)
        self.in_style = tag == "style"

    def handle_endtag(self, tag: str) -> None:
        self.in_style = False

    def handle_data(self, data: str) -> None:
        (self.styles if self.in_style else self.text).append(data)

    def values(self, name: str) -> list[str]:
        return [value for attribute, value in self.attributes if attribute == name]


def reveal(value: str) -> str:
    return "".join(
        character if character.isprintable() else character.encode("unicode_escape").decode()
        for character in value
    )


def evaluated(config: SysmonConfig, events: list[Event]) -> EventsInput:
    items = tuple(
        Evaluated(line, event, config.evaluate(event)) for line, event in enumerate(events)
    )
    return EventsInput("events.jsonl", DIGEST, items)


def condition_values(config: SysmonConfig) -> list[str]:
    return [
        condition.value
        for event_filter in config.filters
        for item in event_filter.items
        for condition in (item.conditions if isinstance(item, Rule) else (item,))
    ]


@given(filters=xml_documents, encoding=encodings, events=st.lists(any_events, max_size=4))
def test_input_strings_render_as_text_in_a_self_contained_page(
    filters: tuple[EventFilter, ...], encoding: str, events: list[Event]
) -> None:
    _, config = render(filters, encoding)
    page = Page(render_report("0.1.0", config, DIGEST, evaluated(config, events)))
    text = "".join(page.text)
    ids = page.values("id")
    assert set(page.tags) <= ALLOWED_TAGS and page.tags.count("style") == 1
    assert {name for name, _ in page.attributes} <= ALLOWED_ATTRIBUTES
    assert len(ids) == len(set(ids))
    assert {f"#{anchor}" for anchor in ids} >= set(page.values("href"))
    assert all(reveal(value) in text for value in condition_values(config))
    assert all(reveal(value) in text for event in events for value in event.fields.values())


def test_the_content_security_policy_allows_exactly_the_embedded_style() -> None:
    document = render_report("0.1.0", config_of(), DIGEST)
    styles = "".join(Page(document).styles)
    digest = base64.b64encode(hashlib.sha256(styles.encode()).digest()).decode()
    meta = f'<meta http-equiv="Content-Security-Policy" content="{CONTENT_SECURITY_POLICY}">'
    assert meta in document
    assert f"style-src 'sha256-{digest}'" in CONTENT_SECURITY_POLICY
    assert CONTENT_SECURITY_POLICY.startswith("default-src 'none';")


def test_summary_cards_count_events_and_configuration() -> None:
    config = parse_config(DOC_SAMPLE.encode(), SOURCE)
    events = [
        Event(6, {"Signature": "Microsoft Windows"}),
        Event(3, {"DestinationPort": "443", "Image": "C:\\chrome.exe"}),
        Event(5, {"Image": "C:\\x.exe"}),
        Event(1, {"Image": "C:\\x.exe"}),
    ]
    document = render_report("0.1.0", config, DIGEST, evaluated(config, events))
    cards = re.findall(
        r'<div class="card (\w*)"><strong>([^<]*)</strong><span>([^<]*)</span>', document
    )
    assert cards == [
        ("", "4", "events"),
        ("ok", "2", "logged"),
        ("bad", "2", "dropped"),
        ("warn", "1", "decided by assumed default"),
        ("", "4", "filters"),
        ("", "5", "conditions"),
        ("", f"3 / {len(EventTag)}", "event types filtered"),
        ("warn", str(len(EventTag) - 3), "event types on assumed default"),
    ]


def test_decision_lines_link_to_their_configuration_rows() -> None:
    config = parse_config(DOC_SAMPLE.encode(), SOURCE)
    document = render_report(
        "0.1.0", config, DIGEST, evaluated(config, [Event(6, {"Signature": "Microsoft"})])
    )
    assert '<a href="#L5">5</a>' in document and '<tr id="L5">' in document


def test_hidden_characters_are_revealed_and_highlighted() -> None:
    event = Event(1, {"Image": "C:\\evil\u202egpj.exe", "CommandLine": "a\x1b[31m\u00a0b"})
    document = render_report("0.1.0", config_of(), DIGEST, evaluated(config_of(), [event]))
    assert 'evil<span class="esc">\\u202e</span>gpj.exe' in document
    assert '<span class="esc">\\x1b</span>[31m<span class="esc">\\xa0</span>b' in document


def test_a_configuration_report_has_no_event_section() -> None:
    document = render_report("0.1.0", config_of(), DIGEST)
    defaults = document.split("<h2>Event types without filter</h2>", 1)[1].split("</section>")[0]
    assert "<h2>Events</h2>" not in document and "No event filter." in document
    assert defaults.count("<tr><td>") == len(EventTag)
