from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

import yaml

from sigma_blindspot.decoding import decode_text
from sigma_blindspot.errors import EventError
from sigma_blindspot.prover.prove import Proof, Recorded, Verdict
from sigma_blindspot.sigma.evaluate import evaluate
from sigma_blindspot.sigma.ir import LoadedRule
from sigma_blindspot.sigma.loader import YAML_LOADER
from sigma_blindspot.sysmon.evtx_json import SYSMON_PROVIDER, load_evtx_json
from sigma_blindspot.sysmon.model import Event, SysmonConfig

DROPPED: Final = "SigmaHQ's recorded attack is dropped by the config"
NO_REGRESSION_DATA: Final = "no regression_data folder"
_CHECKED: Final = frozenset({Verdict.OK, Verdict.PARTIAL})


@dataclass(frozen=True, slots=True)
class Sample:
    rule_id: str
    match_count: int | None
    path: Path


type Samples = Mapping[str, tuple[Sample, ...]]


def _document(info: Path) -> Mapping[str, object]:
    text = decode_text(info.read_bytes(), str(info), EventError)
    try:
        document = yaml.load(text, Loader=YAML_LOADER)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        line = None if mark is None else mark.line + 1
        problem = getattr(error, "problem", None) or type(error).__name__
        raise EventError(f"invalid YAML: {problem}", line, str(info)) from error
    if not isinstance(document, Mapping):
        raise EventError("expected a mapping", None, str(info))
    return document


def _items(document: Mapping[str, object], key: str, info: Path) -> list[Mapping[str, object]]:
    items = document.get(key) or []
    if not isinstance(items, list) or not all(isinstance(item, Mapping) for item in items):
        raise EventError(f"{key} must be a list of mappings", None, str(info))
    return items


def _text(item: Mapping[str, object], key: str, info: Path) -> str:
    value = item.get(key)
    if value is None or isinstance(value, Mapping | list):
        raise EventError(f"{key} must be a value", None, str(info))
    return str(value)


def _count(test: Mapping[str, object], info: Path) -> int | None:
    count = test.get("match_count")
    if count is None:
        return None
    if isinstance(count, bool) or not isinstance(count, int):
        raise EventError("match_count must be an integer", None, str(info))
    return count


def _samples(root: Path, info: Path) -> Iterator[Sample]:
    document = _document(info)
    rule_ids = [_text(item, "id", info) for item in _items(document, "rule_metadata", info)]
    for test in _items(document, "regression_tests_info", info):
        if test.get("provider") != SYSMON_PROVIDER:
            continue
        path = (root / _text(test, "path", info)).with_suffix(".json")
        if not path.resolve().is_relative_to(root.resolve()):
            raise EventError(f"sample path outside {root}", None, str(info))
        count = _count(test, info)
        for rule_id in rule_ids:
            yield Sample(rule_id, count, path)


def samples(root: Path) -> Iterator[Sample]:
    for info in sorted((root / "regression_data").rglob("info.yml")):
        yield from _samples(root, info)


def load_samples(root: Path) -> Samples:
    if not (root / "regression_data").is_dir():
        raise EventError(NO_REGRESSION_DATA, None, str(root))
    found: dict[str, list[Sample]] = {}
    for sample in samples(root):
        found.setdefault(sample.rule_id, []).append(sample)
    return {rule_id: tuple(items) for rule_id, items in found.items()}


def matching(rule: LoadedRule, events: Sequence[Event]) -> tuple[list[Event], bool]:
    relevant = [event for event in events if event.event_id in rule.event_ids]
    outcomes = [(event, evaluate(rule.condition, event)) for event in relevant]
    found = [event for event, outcome in outcomes if outcome is True]
    return found, any(outcome is None for _, outcome in outcomes)


def _missed(proof: Proof, config: SysmonConfig, samples: Sequence[Sample]) -> Proof:
    rule = proof.rule
    recorded: list[Recorded] = []
    for path in dict.fromkeys(sample.path for sample in samples):
        if not path.exists():
            continue
        for event in load_evtx_json(path):
            if event.event_id not in rule.event_ids:
                continue
            matches = evaluate(rule.condition, event)
            decision = config.evaluate(event)
            if matches is not False and decision.logged is not False:
                return proof
            if matches is True:
                reason = str(decision.reason)
                recorded.append(Recorded(str(path), event.event_id, reason, decision.lines))
    if not recorded:
        return proof
    lines = tuple(sorted({line for item in recorded for line in item.lines}))
    return replace(
        proof, verdict=Verdict.MISSED, reason=DROPPED, lines=lines, recorded=tuple(recorded)
    )


def check_samples(
    config: SysmonConfig, proofs: Iterable[Proof], samples: Samples
) -> tuple[Proof, ...]:
    return tuple(
        _missed(proof, config, samples.get(proof.rule.rule_id or "", ()))
        if proof.verdict in _CHECKED
        else proof
        for proof in proofs
    )
