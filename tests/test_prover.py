import textwrap

import pytest
import z3
from conftest import line_of
from hypothesis import event, given
from hypothesis import strategies as st
from strategies import FIELDS, configs, supported_nodes, texts

from sigma_blindspot.prover import prove as prove_module
from sigma_blindspot.prover.prove import Proof, Prover, Verdict
from sigma_blindspot.sigma.evaluate import evaluate
from sigma_blindspot.sigma.ir import Branch, LoadedRule, Node, Or
from sigma_blindspot.sigma.loader import parse_rules
from sigma_blindspot.sysmon.model import Event, SysmonConfig
from sigma_blindspot.sysmon.parser import parse_config

CONFIG = """\
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="end with">\\cmd.exe</Image>
        <ParentImage condition="is">C:\\Windows\\explorer.exe</ParentImage>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\\CurrentVersion\\Run</TargetObject>
      </RegistryEvent>
    </RuleGroup>
    <FileCreate onmatch="include"/>
  </EventFiltering>
</Sysmon>
"""


def proof_of(detection: str, category: str = "process_creation", config: str = CONFIG) -> Proof:
    text = (
        f"title: fixture\nlogsource:\n  category: {category}\n  product: windows\n"
        f"detection:\n{textwrap.indent(textwrap.dedent(detection), '  ')}"
    )
    (rule,) = parse_rules(text.encode(), "rule.yml")
    assert isinstance(rule, LoadedRule)
    return Prover(parse_config(config.encode(), "config.xml")).prove(rule)


def at(needle: str) -> int:
    return line_of(CONFIG, needle)


def test_a_rule_the_config_logs_is_ok_with_a_confirmed_example() -> None:
    proof = proof_of("sel:\n  Image|endswith: '\\powershell.exe'\ncondition: sel\n")
    assert proof.verdict is Verdict.OK and proof.example is not None
    event = Event(proof.example.event_id, dict(proof.example.fields))
    assert event.fields["Image"].endswith("\\powershell.exe")
    assert parse_config(CONFIG.encode(), "config.xml").evaluate(event).logged is True


def test_a_rule_the_config_always_drops_is_blind_with_the_responsible_line() -> None:
    proof = proof_of("sel:\n  Image|endswith: '\\cmd.exe'\ncondition: sel\n")
    assert (proof.verdict, proof.lines) == (Verdict.BLIND, (at("cmd.exe"),))
    assert proof.reason == "every matching event is dropped by the config"


def test_a_rule_with_a_blind_branch_is_partial() -> None:
    detection = """\
        sel_cmd:
          Image|endswith: '\\cmd.exe'
        sel_ps:
          Image|endswith: '\\powershell.exe'
        condition: 1 of sel_*
        """
    proof = proof_of(detection)
    assert (proof.verdict, proof.lines) == (Verdict.PARTIAL, (at("cmd.exe"),))
    assert proof.reason == "never fires: #1 sel_cmd"
    assert [branch.verdict for branch in proof.branches] == [Verdict.BLIND, Verdict.OK]


def test_a_self_contradicting_rule_is_rule_unsat() -> None:
    proof = proof_of("a:\n  Image: x\nb:\n  Image: y\ncondition: a and b\n")
    assert (proof.verdict, proof.reason) == (Verdict.RULE_UNSAT, "the rule contradicts itself")


def test_an_event_type_off_by_default_makes_the_rule_blind() -> None:
    proof = proof_of("sel:\n  ImageLoaded|endswith: '.dll'\ncondition: sel\n", "image_load")
    assert proof.verdict is Verdict.BLIND
    assert proof.reason == "ImageLoad (7) is not logged without a filter"
    assert proof.branches[0].findings[0].verdict is Verdict.DISABLED


def test_an_empty_include_disables_its_event_type() -> None:
    proof = proof_of("sel:\n  TargetFilename|contains: 'x'\ncondition: sel\n", "file_event")
    assert (proof.verdict, proof.lines) == (Verdict.BLIND, (at("<FileCreate"),))
    assert proof.reason == "the config drops every event of this type"


def test_an_event_type_logged_by_default_lets_the_rule_fire() -> None:
    proof = proof_of("sel:\n  Image|endswith: '\\x.exe'\ncondition: sel\n", "process_termination")
    assert proof.verdict is Verdict.OK and proof.example is not None
    assert proof.example.event_id == 5


def test_an_event_type_not_logged_by_default_makes_the_rule_blind() -> None:
    proof = proof_of("sel:\n  GrantedAccess: '0x1fffff'\ncondition: sel\n", "process_access")
    assert (proof.verdict, proof.reason) == (
        Verdict.BLIND,
        "ProcessAccess (10) is not logged without a filter",
    )


def test_an_unverified_default_gives_unknown() -> None:
    proof = proof_of("sel:\n  ImageLoaded|endswith: '.sys'\ncondition: sel\n", "driver_load")
    assert (proof.verdict, proof.reason) == (Verdict.UNKNOWN, "Sysmon default unverified")


def test_an_unsupported_construct_gives_unknown_unless_the_type_is_off() -> None:
    regex = "sel:\n  {field}|re: 'a.*'\ncondition: sel\n"
    unknown = proof_of(regex.format(field="Image"))
    assert (unknown.verdict, unknown.reason) == (
        Verdict.UNKNOWN,
        "unsupported: regular expression (re)",
    )
    disabled = proof_of(regex.format(field="ImageLoaded"), "image_load")
    assert disabled.verdict is Verdict.BLIND


def test_events_sysmon_cannot_filter_are_always_logged() -> None:
    proof = proof_of("sel:\n  State: Started\ncondition: sel\n", "sysmon_status")
    assert proof.verdict is Verdict.OK
    assert [finding.event_id for finding in proof.branches[0].findings] == [4, 16]


def test_the_event_id_field_selects_the_event_type() -> None:
    detection = "sel:\n  EventID: 13\n  TargetObject|contains: '\\Run'\ncondition: sel\n"
    proof = proof_of(detection, "registry_event")
    verdicts = [finding.verdict for finding in proof.branches[0].findings]
    assert verdicts == [Verdict.RULE_UNSAT, Verdict.OK, Verdict.RULE_UNSAT]
    assert proof.verdict is Verdict.OK and proof.example is not None
    assert proof.example.event_id == 13


def test_a_value_z3_cannot_represent_gives_unknown() -> None:
    proof = proof_of("sel:\n  Image: 'a\U000e0001'\ncondition: sel\n")
    assert proof.verdict is Verdict.UNKNOWN and "U+E0001" in proof.reason


def test_a_model_the_emulator_rejects_is_never_reported_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(prove_module, "evaluate", lambda node, event: False)
    proof = proof_of("sel:\n  Image|endswith: '\\powershell.exe'\ncondition: sel\n")
    assert (proof.verdict, proof.reason) == (Verdict.UNKNOWN, "model could not be confirmed")


def test_proofs_do_not_depend_on_the_rules_proved_before() -> None:
    text = (
        "title: a\nlogsource: {category: process_creation, product: windows}\n"
        "detection: {sel: {Image|endswith: '\\powershell.exe'}, condition: sel}\n---\n"
        "title: b\nlogsource: {category: process_creation, product: windows}\n"
        "detection: {sel: {CommandLine|contains: ' -enc '}, condition: sel}\n"
    )
    rules = [
        rule for rule in parse_rules(text.encode(), "rules.yml") if isinstance(rule, LoadedRule)
    ]
    config = parse_config(CONFIG.encode(), "config.xml")
    forward = Prover(config)
    backward = Prover(config)
    first = [forward.prove(rule) for rule in rules]
    second = [backward.prove(rule) for rule in reversed(rules)][::-1]
    assert first == second


def test_z3_giving_up_gives_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(z3.Solver, "check", lambda self, *args: z3.unknown)
    monkeypatch.setattr(z3.Solver, "reason_unknown", lambda self: "timeout")
    proof = proof_of("sel:\n  Image|endswith: '\\powershell.exe'\ncondition: sel\n")
    assert (proof.verdict, proof.reason) == (Verdict.UNKNOWN, "Z3 gave up on the config: timeout")


complete_events = st.builds(
    Event,
    event_id=st.sampled_from((1, 12, 13, 14)),
    fields=st.fixed_dictionaries({name: texts for name in FIELDS}),
)


def generated_rule(node: Node, category: str, event_ids: tuple[int, ...]) -> LoadedRule:
    parts = node.args if isinstance(node, Or) and node.args else (node,)
    branches = tuple(Branch(f"#{number}", part) for number, part in enumerate(parts, start=1))
    return LoadedRule("rule.yml", "generated", None, category, event_ids, (), branches)


@given(
    config=configs,
    node=supported_nodes,
    category=st.sampled_from([("process_creation", (1,)), ("registry_event", (12, 13, 14))]),
    events=st.lists(complete_events, max_size=6),
)
def test_verdicts_never_contradict_the_emulator_and_the_evaluator(
    config: SysmonConfig,
    node: Node,
    category: tuple[str, tuple[int, ...]],
    events: list[Event],
) -> None:
    name, event_ids = category
    rule = generated_rule(node, name, event_ids)
    proof = Prover(config).prove(rule)
    event(proof.verdict.value)
    firing = [
        event
        for event in events
        if event.event_id in event_ids
        and evaluate(rule.condition, event) is True
        and config.evaluate(event).logged is True
    ]
    if proof.verdict in (Verdict.BLIND, Verdict.RULE_UNSAT):
        assert firing == []
    if proof.verdict in (Verdict.OK, Verdict.PARTIAL):
        assert proof.example is not None
        example = Event(proof.example.event_id, dict(proof.example.fields))
        assert evaluate(rule.condition, example) is True
        assert config.evaluate(example).logged is True
