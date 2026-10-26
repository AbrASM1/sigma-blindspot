from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

import z3

from sigma_blindspot.prover.encode import Tracked, encode_config
from sigma_blindspot.prover.search import Encoded, Outcome, Search
from sigma_blindspot.prover.strings import Unrepresentable
from sigma_blindspot.sigma.evaluate import evaluate
from sigma_blindspot.sigma.ir import Branch, LoadedRule, Node, unsupported
from sigma_blindspot.sysmon.conditions import fold
from sigma_blindspot.sysmon.events import (
    EVENT_IDS_BY_TAG,
    TAG_BY_EVENT_ID,
    Default,
    EventTag,
    default_without_filter,
)
from sigma_blindspot.sysmon.model import Event, Lines, SysmonConfig

DEFAULT_TIMEOUT_MS: Final = 2000

type Fields = tuple[tuple[str, str], ...]


class Verdict(StrEnum):
    OK = "OK"
    PARTIAL = "PARTIAL"
    BLIND = "BLIND"
    DISABLED = "DISABLED"
    RULE_UNSAT = "RULE_UNSAT"
    UNKNOWN = "UNKNOWN"


class Why(StrEnum):
    MATCHES = "not provably blind: the example event, found by Z3, matches the rule and is logged"
    DROPPED = "every matching event is dropped by the config"
    DROPS_ALL = "the config drops every event of this type"
    CONTRADICTION = "the rule contradicts itself"
    UNCONFIRMED = "model could not be confirmed"
    UNVERIFIED_DEFAULT = "Sysmon default unverified (probe P1)"


_CANNOT_FIRE: Final = frozenset({Verdict.BLIND, Verdict.DISABLED, Verdict.RULE_UNSAT})


@dataclass(frozen=True, slots=True)
class Example:
    event_id: int
    fields: Fields


@dataclass(frozen=True, slots=True)
class Finding:
    event_id: int
    verdict: Verdict
    reason: str
    lines: Lines = ()
    example: Example | None = None


@dataclass(frozen=True, slots=True)
class BranchProof:
    label: str
    verdict: Verdict
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class Proof:
    rule: LoadedRule
    verdict: Verdict
    reason: str
    lines: Lines
    example: Example | None
    branches: tuple[BranchProof, ...]


@dataclass(frozen=True, slots=True)
class _Scope:
    finding: Finding | None = None
    solver: Any = None
    labels: Mapping[str, Lines] = MappingProxyType({})
    asserted: tuple[Encoded, ...] = ()


def _union(groups: Iterable[Lines]) -> Lines:
    return tuple(sorted({line for lines in groups for line in lines}))


def _combine(verdicts: Iterable[Verdict]) -> Verdict:
    found = set(verdicts)
    if Verdict.OK in found:
        return Verdict.OK
    if found <= {Verdict.RULE_UNSAT}:
        return Verdict.RULE_UNSAT
    if found <= _CANNOT_FIRE:
        return Verdict.BLIND
    return Verdict.UNKNOWN


def _reasons(findings: Iterable[Finding]) -> str:
    return "; ".join(dict.fromkeys(finding.reason for finding in findings))


def _proof(rule: LoadedRule, branches: tuple[BranchProof, ...]) -> Proof:
    findings = [finding for branch in branches for finding in branch.findings]
    combined = _combine(branch.verdict for branch in branches)
    example = next((finding.example for finding in findings if finding.example), None)
    blind = [branch for branch in branches if branch.verdict is Verdict.BLIND]
    if combined is Verdict.OK and blind:
        reason = "never fires: " + ", ".join(branch.label for branch in blind)
        lines = _union(finding.lines for branch in blind for finding in branch.findings)
        return Proof(rule, Verdict.PARTIAL, reason, lines, example, branches)
    if combined is Verdict.OK:
        return Proof(rule, combined, Why.MATCHES, (), example, branches)
    if combined is Verdict.UNKNOWN:
        unknown = (finding for finding in findings if finding.verdict is Verdict.UNKNOWN)
        return Proof(rule, combined, _reasons(unknown), (), None, branches)
    lines = _union(finding.lines for finding in findings)
    return Proof(rule, combined, _reasons(findings), lines, None, branches)


def _default(event_id: int, tag: EventTag) -> Finding | None:
    match default_without_filter(tag):
        case Default.NOT_LOGGED:
            ids = ", ".join(map(str, EVENT_IDS_BY_TAG[tag]))
            return Finding(
                event_id, Verdict.DISABLED, f"{tag} ({ids}) is not logged without a filter"
            )
        case Default.UNKNOWN:
            return Finding(event_id, Verdict.UNKNOWN, Why.UNVERIFIED_DEFAULT)
        case Default.LOGGED:
            return None


def _tracked_scope(search: Search, tracked: tuple[Tracked, ...]) -> _Scope:
    encoded = tuple(search.encode(item.node) for item in tracked)
    solver = search.solver()
    labels = {f"config:{index}": item.lines for index, item in enumerate(tracked)}
    for label, item in zip(labels, encoded, strict=True):
        solver.assert_and_track(item.formula, label)
    return _Scope(None, solver, MappingProxyType(labels), encoded)


def _config_status(timeout_ms: int, tracked: tuple[Tracked, ...], event_id: int) -> Finding | None:
    search = Search(timeout_ms)
    try:
        scope = _tracked_scope(search, tracked)
    except Unrepresentable as error:
        return Finding(event_id, Verdict.UNKNOWN, f"unsupported: {error}")
    outcome = search.check(scope.solver, (), scope.asserted)
    if outcome.result == z3.unsat:
        lines = _union(scope.labels[label] for label in outcome.core)
        return Finding(event_id, Verdict.DISABLED, Why.DROPS_ALL, lines)
    if outcome.result != z3.sat:
        why = f"Z3 gave up on the config: {outcome.why_unknown}"
        return Finding(event_id, Verdict.UNKNOWN, why)
    return None


class _Session:
    def __init__(self, prover: "Prover") -> None:
        self._prover = prover
        self._config = prover.config
        self._search = Search(prover.timeout_ms)
        self._alone = self._search.solver()
        self._scopes: dict[int, _Scope] = {}

    def _scope(self, event_id: int) -> _Scope:
        if event_id not in self._scopes:
            tag = TAG_BY_EVENT_ID.get(event_id)
            if tag is None:
                scope = _Scope()
            elif not self._config.filters_for(tag):
                scope = _Scope(_default(event_id, tag))
            else:
                status = self._prover.status(tag)
                scope = (
                    _Scope(replace(status, event_id=event_id))
                    if status is not None
                    else _tracked_scope(self._search, self._prover.tracked(tag))
                )
            self._scopes[event_id] = scope
        return self._scopes[event_id]

    def _settle(self, node: Node, event_id: int, outcome: Outcome) -> Finding:
        if outcome.result != z3.sat:
            return Finding(event_id, Verdict.UNKNOWN, f"Z3 gave up: {outcome.why_unknown}")
        values = tuple((name, fold(value)) for name, value in outcome.values)
        event = Event(event_id, dict(values))
        if evaluate(node, event) is not True or self._config.evaluate(event).logged is not True:
            return Finding(event_id, Verdict.UNKNOWN, Why.UNCONFIRMED)
        return Finding(event_id, Verdict.OK, Why.MATCHES, example=Example(event_id, values))

    def _encoded(self, node: Node, event_id: int) -> Encoded | str:
        reasons = unsupported(node)
        if reasons:
            return "unsupported: " + ", ".join(reasons)
        try:
            return self._search.encode(node, event_id)
        except Unrepresentable as error:
            return f"unsupported: {error}"

    def finding(self, node: Node, event_id: int) -> Finding:
        scope = self._scope(event_id)
        rule = self._encoded(node, event_id)
        if isinstance(rule, str):
            if scope.finding is not None and scope.finding.verdict is Verdict.DISABLED:
                return scope.finding
            return Finding(event_id, Verdict.UNKNOWN, rule)
        alone = self._search.check(self._alone, (rule,))
        if alone.result == z3.unsat:
            return Finding(event_id, Verdict.RULE_UNSAT, Why.CONTRADICTION)
        if scope.finding is not None:
            return scope.finding
        if scope.solver is None:
            return self._settle(node, event_id, alone)
        outcome = self._search.check(scope.solver, (rule,), scope.asserted)
        if outcome.result == z3.unsat:
            lines = _union(scope.labels[label] for label in outcome.core)
            return Finding(event_id, Verdict.BLIND, Why.DROPPED, lines)
        return self._settle(node, event_id, outcome)

    def branch(self, branch: Branch, event_ids: tuple[int, ...]) -> BranchProof:
        findings = tuple(self.finding(branch.condition, event_id) for event_id in event_ids)
        return BranchProof(branch.label, _combine(item.verdict for item in findings), findings)


class Prover:
    def __init__(self, config: SysmonConfig, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> None:
        self.config = config
        self.timeout_ms = timeout_ms
        self._tracked: dict[EventTag, tuple[Tracked, ...]] = {}
        self._status: dict[EventTag, Finding | None] = {}

    def tracked(self, tag: EventTag) -> tuple[Tracked, ...]:
        if tag not in self._tracked:
            self._tracked[tag] = encode_config(self.config.filters_for(tag))
        return self._tracked[tag]

    def status(self, tag: EventTag) -> Finding | None:
        if tag not in self._status:
            first = EVENT_IDS_BY_TAG[tag][0]
            self._status[tag] = _config_status(self.timeout_ms, self.tracked(tag), first)
        return self._status[tag]

    def prove(self, rule: LoadedRule) -> Proof:
        session = _Session(self)
        return _proof(
            rule, tuple(session.branch(branch, rule.event_ids) for branch in rule.branches)
        )
