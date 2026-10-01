import pytest
from conftest import DOC_RULE_GROUPS, DOC_SAMPLE, Writer, line_of
from hypothesis import given
from strategies import SOURCE, config_of, encode, encodings, render, xml_documents

from sigma_blindspot.errors import ConfigError
from sigma_blindspot.sysmon.conditions import Operator
from sigma_blindspot.sysmon.events import EventTag
from sigma_blindspot.sysmon.model import (
    Condition,
    EventFilter,
    OnMatch,
    Relation,
    Rule,
    SysmonConfig,
)
from sigma_blindspot.sysmon.parser import load_config, parse_config


def sysmon(*lines: str) -> str:
    head = ['<Sysmon schemaversion="4.90">', "  <EventFiltering>"]
    return "\n".join([*head, *lines, "  </EventFiltering>", "</Sysmon>", ""])


def parse(text: str) -> SysmonConfig:
    return parse_config(text.encode(), SOURCE)


def test_parses_the_documentation_sample() -> None:
    def at(needle: str) -> int:
        return line_of(DOC_SAMPLE, needle)

    expected = SysmonConfig(
        "4.82",
        (
            EventFilter(
                EventTag.DRIVER_LOAD,
                OnMatch.EXCLUDE,
                None,
                (
                    Condition("Signature", Operator.CONTAINS, "microsoft", at(">microsoft<")),
                    Condition("Signature", Operator.CONTAINS, "windows", at(">windows<")),
                ),
                at("<DriverLoad"),
            ),
            EventFilter(
                EventTag.PROCESS_TERMINATE, OnMatch.INCLUDE, None, (), at("<ProcessTerminate")
            ),
            EventFilter(
                EventTag.NETWORK_CONNECT,
                OnMatch.INCLUDE,
                None,
                (
                    Condition("DestinationPort", Operator.IS, "443", at(">443<")),
                    Condition("DestinationPort", Operator.IS, "80", at(">80<")),
                ),
                at('<NetworkConnect onmatch="include"'),
            ),
            EventFilter(
                EventTag.NETWORK_CONNECT,
                OnMatch.EXCLUDE,
                None,
                (Condition("Image", Operator.END_WITH, "iexplore.exe", at("iexplore.exe")),),
                at('<NetworkConnect onmatch="exclude"'),
            ),
        ),
        SOURCE,
    )
    assert parse(DOC_SAMPLE) == expected


def test_rule_groups_set_the_relation_of_their_filters() -> None:
    config = parse(DOC_RULE_GROUPS)
    relations = [(item.tag, item.group_relation) for item in config.filters]
    assert relations == [
        (EventTag.PROCESS_CREATE, Relation.AND),
        (EventTag.PROCESS_TERMINATE, Relation.OR),
        (EventTag.IMAGE_LOAD, None),
    ]


def test_rule_elements_keep_their_relation_name_and_conditions() -> None:
    text = sysmon(
        '    <RuleGroup name="" groupRelation="or">',
        '      <ProcessCreate onmatch="include">',
        '        <Rule name="technique_id=T1059.001" groupRelation="and">',
        '          <Image condition="image">powershell.exe</Image>',
        '          <CommandLine condition="contains any">-enc;-e </CommandLine>',
        "        </Rule>",
        "      </ProcessCreate>",
        "    </RuleGroup>",
    )
    rule = Rule(
        Relation.AND,
        (
            Condition("Image", Operator.IMAGE, "powershell.exe", line_of(text, "powershell.exe")),
            Condition("CommandLine", Operator.CONTAINS_ANY, "-enc;-e ", line_of(text, "-enc")),
        ),
        line_of(text, "<Rule name"),
        "technique_id=T1059.001",
    )
    assert parse(text).filters[0].items == (rule,)


def test_condition_values_are_kept_literally() -> None:
    text = sysmon(
        '    <ProcessCreate onmatch="exclude">',
        "      <CommandLine>  a &amp; b <![CDATA[<x>]]>&#13;&#x9;",
        "</CommandLine>",
        "    </ProcessCreate>",
    )
    condition = parse(text).filters[0].items[0]
    assert condition == Condition(
        "CommandLine", Operator.IS, "  a & b <x>\r\t\n", line_of(text, "<CommandLine>")
    )


def test_configuration_entries_are_ignored() -> None:
    text = "\n".join(
        [
            '<Sysmon schemaversion="4.90">',
            "  <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>",
            "  <CheckRevocation/>",
            '  <ArchiveDirectory any="attribute"><Nested>text</Nested></ArchiveDirectory>',
            "</Sysmon>",
        ]
    )
    assert parse(text) == config_of()


def test_reads_utf16_with_byte_order_mark() -> None:
    text = sysmon(
        '    <FileCreate onmatch="include">',
        '      <TargetFilename condition="contains">\\Téléchargements\\</TargetFilename>',
        "    </FileCreate>",
    )
    config = parse_config(encode(text, "utf-16-le"), SOURCE)
    assert config.filters[0].items == (
        Condition(
            "TargetFilename", Operator.CONTAINS, "\\Téléchargements\\", line_of(text, "Target")
        ),
    )


def test_load_config_reads_a_file(write: Writer) -> None:
    path = write("sysmon.xml", DOC_RULE_GROUPS)
    config = load_config(path)
    assert config.source == str(path) and len(config.filters) == 3


BILLION_LAUGHS = """\
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<Sysmon schemaversion="4.90">&lol2;</Sysmon>
"""

EXTERNAL_ENTITY = """\
<?xml version="1.0"?>
<!DOCTYPE Sysmon [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Sysmon schemaversion="4.90">&xxe;</Sysmon>
"""

FILTER_START = '    <ProcessCreate onmatch="include">'
FILTER_END = "    </ProcessCreate>"


@pytest.mark.parametrize(
    ("text", "needle", "message"),
    [
        pytest.param(BILLION_LAUGHS, "<!DOCTYPE", "DOCTYPE", id="billion-laughs"),
        pytest.param(EXTERNAL_ENTITY, "<!DOCTYPE", "DOCTYPE", id="external-entity"),
        pytest.param(
            '<Sysmon schemaversion="4.90">\n  <EventFiltering>\n</Sysmon>\n',
            "</Sysmon>",
            "mismatched tag",
            id="not-well-formed",
        ),
        pytest.param(
            sysmon(FILTER_START, "      <Image>&foo;</Image>", FILTER_END),
            "&foo;",
            "undefined entity",
            id="undefined-entity",
        ),
        pytest.param(
            '<Config schemaversion="4.90"/>\n', "<Config", "must be <Sysmon>", id="wrong-root"
        ),
        pytest.param(
            "<Sysmon>\n</Sysmon>\n",
            "<Sysmon>",
            "requires attribute 'schemaversion'",
            id="no-schema-version",
        ),
        pytest.param(
            '<Sysmon schemaversion="4"/>\n', "<Sysmon", "MAJOR.MINOR", id="bad-schema-version"
        ),
        pytest.param(
            '<Sysmon schemaversion="4.90" binaryversion="15"/>\n',
            "<Sysmon",
            "does not allow attribute 'binaryversion'",
            id="unknown-root-attribute",
        ),
        pytest.param(
            '<Sysmon schemaversion="4.90">\n  <EventFiltering/>\n  <EventFiltering />\n</Sysmon>',
            "<EventFiltering />",
            "appears more than once",
            id="duplicate-event-filtering",
        ),
        pytest.param(
            '<Sysmon schemaversion="4.90">\n  <EventFiltering>stray</EventFiltering>\n</Sysmon>',
            "stray",
            "<EventFiltering> cannot contain text",
            id="text-in-event-filtering",
        ),
        pytest.param(
            sysmon('    <ProcessCreation onmatch="include"/>'),
            "ProcessCreation",
            "is not a Sysmon event filter",
            id="unknown-event-filter",
        ),
        pytest.param(
            sysmon(
                '    <RuleGroup groupRelation="or">',
                '      <RuleGroup groupRelation="and"/>',
                "    </RuleGroup>",
            ),
            'groupRelation="and"',
            "<RuleGroup> is not a Sysmon event filter",
            id="nested-rule-group",
        ),
        pytest.param(
            sysmon('    <RuleGroup name="x"/>'),
            "<RuleGroup",
            "requires attribute 'groupRelation'",
            id="rule-group-without-relation",
        ),
        pytest.param(
            sysmon('    <RuleGroup groupRelation="xor"/>'),
            "<RuleGroup",
            "groupRelation='xor' is not one of 'and', 'or'",
            id="rule-group-bad-relation",
        ),
        pytest.param(
            sysmon("    <ProcessCreate/>"),
            "<ProcessCreate",
            "requires attribute 'onmatch'",
            id="filter-without-onmatch",
        ),
        pytest.param(
            sysmon('    <ProcessCreate onmatch="Include"/>'),
            "<ProcessCreate",
            "onmatch='Include' is not one of 'include', 'exclude'",
            id="filter-bad-onmatch",
        ),
        pytest.param(
            sysmon('    <ProcessCreate onmatch="include">stray</ProcessCreate>'),
            "stray",
            "<ProcessCreate> cannot contain text",
            id="text-in-filter",
        ),
        pytest.param(
            sysmon(
                FILTER_START,
                '      <Rule name="r">',
                "        <Image>a</Image>",
                "      </Rule>",
                FILTER_END,
            ),
            "<Rule",
            "requires attribute 'groupRelation'",
            id="rule-without-relation",
        ),
        pytest.param(
            sysmon(FILTER_START, '      <Rule groupRelation="and"/>', FILTER_END),
            "<Rule",
            "needs at least one condition",
            id="empty-rule",
        ),
        pytest.param(
            sysmon(
                FILTER_START,
                '      <Rule groupRelation="and">',
                '        <Rule groupRelation="or"/>',
                "      </Rule>",
                FILTER_END,
            ),
            'groupRelation="or"',
            "<Rule> is not allowed here",
            id="nested-rule",
        ),
        pytest.param(
            sysmon(FILTER_START, '      <Image conditon="contains">a</Image>', FILTER_END),
            "conditon",
            "does not allow attribute 'conditon'",
            id="misspelled-condition-attribute",
        ),
        pytest.param(
            sysmon(FILTER_START, '      <Image condition="contain">a</Image>', FILTER_END),
            "<Image",
            "condition='contain' is not one of 'is', 'is any'",
            id="unknown-condition",
        ),
        pytest.param(
            sysmon(
                FILTER_START,
                "      <Image>",
                "        <Path>a</Path>",
                "      </Image>",
                FILTER_END,
            ),
            "<Path>",
            "field <Image> cannot contain elements",
            id="field-with-children",
        ),
    ],
)
def test_rejects_invalid_configs_with_their_line(text: str, needle: str, message: str) -> None:
    with pytest.raises(ConfigError) as caught:
        parse(text)
    assert (caught.value.source, caught.value.line) == (SOURCE, line_of(text, needle))
    assert message in caught.value.message


def test_rejects_an_empty_document() -> None:
    with pytest.raises(ConfigError, match="no element found"):
        parse("")


@given(filters=xml_documents, encoding=encodings)
def test_parsing_a_rendered_config_gives_back_its_model(
    filters: tuple[EventFilter, ...], encoding: str
) -> None:
    text, expected = render(filters, encoding)
    assert parse_config(encode(text, encoding), SOURCE) == expected
