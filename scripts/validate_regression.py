import sys
import time
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import z3
from fetch_configs import fetch_configs
from fetch_sigmahq import COMMIT, fetch_sigmahq

from sigma_blindspot.errors import EventError
from sigma_blindspot.prover.prove import Proof, Prover, Verdict
from sigma_blindspot.prover.search import Search
from sigma_blindspot.samples import Sample, matching, samples
from sigma_blindspot.sigma.evaluate import evaluate
from sigma_blindspot.sigma.ir import And, Equals, LoadedRule, Match, Node, unsupported
from sigma_blindspot.sigma.loader import load_rules
from sigma_blindspot.sysmon.conditions import fold
from sigma_blindspot.sysmon.evtx_json import load_evtx_json
from sigma_blindspot.sysmon.model import Event, SysmonConfig
from sigma_blindspot.sysmon.parser import load_config

ROOT: Final = Path(__file__).resolve().parents[1]
REPORT: Final = ROOT / ".cache" / "regression.md"
_CANNOT_FIRE: Final = frozenset({Verdict.BLIND, Verdict.DISABLED, Verdict.RULE_UNSAT})


@dataclass(frozen=True, slots=True)
class Mismatch:
    check: str
    rule: str
    detail: str


def pinned_satisfiable(condition: Node, event: Event) -> bool | None:
    search = Search(10_000)
    pins = tuple(Match(name, Equals(fold(value))) for name, value in event.fields.items())
    encoded = search.encode(And((condition, *pins)), event.event_id)
    outcome = search.check(search.solver(), (encoded,))
    if outcome.result == z3.unknown:
        return None
    return bool(outcome.result == z3.sat)


def cannot_fire(proof: Proof, event_id: int) -> bool:
    findings = [
        finding
        for branch in proof.branches
        for finding in branch.findings
        if finding.event_id == event_id
    ]
    return all(finding.verdict in _CANNOT_FIRE for finding in findings)


def _encoding(rule: LoadedRule, found: Sequence[Event], counts: Counter[str]) -> Iterator[Mismatch]:
    for event in found:
        for branch in rule.branches:
            if unsupported(branch.condition) or evaluate(branch.condition, event) is not True:
                continue
            counts["branches pinned to a sample"] += 1
            satisfiable = pinned_satisfiable(branch.condition, event)
            if satisfiable is not True:
                detail = (
                    f"branch {branch.label} pinned to the sample of EventID {event.event_id}, "
                    f"the encoding is {satisfiable}"
                )
                yield Mismatch("2 encoding", rule.source, detail)


def _prover(
    rule: LoadedRule, found: Sequence[Event], provers: dict[str, Prover], counts: Counter[str]
) -> Iterator[Mismatch]:
    for name, prover in provers.items():
        logged = [event for event in found if prover.config.evaluate(event).logged is True]
        if not logged:
            continue
        counts[f"samples logged by {name}"] += 1
        proof = prover.prove(rule)
        if any(cannot_fire(proof, event.event_id) for event in logged):
            detail = f"{name} logs the sample, the prover says {proof.verdict}: {proof.reason}"
            yield Mismatch("3 prover", rule.source, detail)


def _check(
    rule: LoadedRule, sample: Sample, provers: dict[str, Prover], counts: Counter[str]
) -> Iterator[Mismatch]:
    try:
        events = load_evtx_json(sample.path)
    except EventError as error:
        yield Mismatch("sample", rule.source, str(error))
        return
    counts["samples checked"] += 1
    found, undecided = matching(rule, events)
    if undecided and not found:
        counts["evaluator undecided (unsupported construct)"] += 1
        return
    minimum = 1 if sample.match_count is None else sample.match_count
    if len(found) < minimum:
        detail = f"the evaluator matches {len(found)} events, SigmaHQ expects at least {minimum}"
        yield Mismatch("1 evaluator", rule.source, detail)
    elif sample.match_count is not None and len(found) > sample.match_count:
        counts["evaluator matches more events than match_count (a SigmaHQ warning)"] += 1
    yield from _encoding(rule, found, counts)
    yield from _prover(rule, found, provers, counts)


def validate(
    sigmahq: Path, configs: dict[str, SysmonConfig]
) -> tuple[Counter[str], list[Mismatch]]:
    loaded = load_rules([sigmahq / "rules" / "windows"])
    rules = {rule.rule_id: rule for rule in loaded if isinstance(rule, LoadedRule)}
    provers = {name: Prover(config) for name, config in configs.items()}
    counts: Counter[str] = Counter()
    mismatches: list[Mismatch] = []
    for sample in samples(sigmahq):
        rule = rules.get(sample.rule_id)
        if rule is None:
            counts["rule not analysed (out of scope or skipped)"] += 1
        elif not sample.path.exists():
            counts["no JSON sample"] += 1
        else:
            mismatches.extend(_check(rule, sample, provers, counts))
    return counts, mismatches


def report(counts: Counter[str], mismatches: Sequence[Mismatch], seconds: float) -> str:
    lines = [
        "# SigmaHQ regression validation",
        "",
        f"SigmaHQ commit `{COMMIT}`, {seconds:.0f} s.",
        "",
        *(f"- {name}: {count}" for name, count in sorted(counts.items())),
        f"- mismatches: {len(mismatches)}",
        "",
        "| Check | Rule | Detail |",
        "| --- | --- | --- |",
        *(f"| {item.check} | `{item.rule}` | {item.detail} |" for item in mismatches),
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    started = time.monotonic()
    sigmahq = fetch_sigmahq()
    configs = {name: load_config(path) for name, path in fetch_configs().items()}
    counts, mismatches = validate(sigmahq, configs)
    text = report(counts, mismatches, time.monotonic() - started)
    REPORT.write_text(text, encoding="utf-8")
    sys.stdout.write(text.encode("ascii", "backslashreplace").decode("ascii"))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
