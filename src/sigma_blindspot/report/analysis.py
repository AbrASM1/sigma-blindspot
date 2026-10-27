import json
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Final

from sigma_blindspot.prover.prove import (
    BranchProof,
    Example,
    Finding,
    Proof,
    Recorded,
    Verdict,
)
from sigma_blindspot.sigma.ir import Skipped
from sigma_blindspot.sysmon.model import Lines

type Result = Proof | Skipped


@dataclass(frozen=True, slots=True)
class Analysis:
    version: str
    config_source: str
    config_sha256: str
    results: tuple[Result, ...]
    samples: str | None = None


SCHEMA_VERSION: Final = 2
SKIPPED: Final = "SKIPPED"
FAILING: Final = frozenset({Verdict.BLIND, Verdict.MISSED, Verdict.PARTIAL})
ORDER: Final = (
    Verdict.BLIND,
    Verdict.MISSED,
    Verdict.PARTIAL,
    Verdict.RULE_UNSAT,
    Verdict.UNKNOWN,
    Verdict.OK,
    SKIPPED,
)


def verdict_of(result: Result) -> str:
    return SKIPPED if isinstance(result, Skipped) else result.verdict


def _source(result: Result) -> str:
    return result.source if isinstance(result, Skipped) else result.rule.source


def _title(result: Result) -> str | None:
    return result.title if isinstance(result, Skipped) else result.rule.title


def _rank(item: tuple[int, Result]) -> tuple[int, str, str, int]:
    index, result = item
    return ORDER.index(verdict_of(result)), _source(result), _title(result) or "", index


def ordered(results: Sequence[Result]) -> list[Result]:
    return [result for _, result in sorted(enumerate(results), key=_rank)]


def shown(samples: bool) -> tuple[str, ...]:
    return ORDER if samples else tuple(verdict for verdict in ORDER if verdict != Verdict.MISSED)


def counts(results: Sequence[Result], samples: bool = False) -> dict[str, int]:
    found = Counter(map(verdict_of, results))
    return {str(verdict): found[verdict] for verdict in shown(samples)}


def failing(results: Sequence[Result]) -> list[Proof]:
    return [
        result
        for result in ordered(results)
        if isinstance(result, Proof) and result.verdict in FAILING
    ]


def rules_by_line(results: Sequence[Result]) -> list[tuple[int | None, list[Proof]]]:
    by_line: dict[int | None, list[Proof]] = {}
    for proof in failing(results):
        for line in proof.lines or (None,):
            by_line.setdefault(line, []).append(proof)
    return sorted(by_line.items(), key=lambda item: (item[0] is None, -len(item[1]), item[0] or 0))


def _where(config_source: str, lines: Lines) -> str:
    places = ", ".join(f"{config_source}:{line}" for line in lines)
    return f" ({places})" if places else ""


def result_lines(analysis: Analysis, only: frozenset[str] = frozenset()) -> Iterator[str]:
    for result in ordered(analysis.results):
        if only and verdict_of(result) not in only:
            continue
        title = _title(result)
        named = "" if title is None else f" {json.dumps(title)}"
        if isinstance(result, Skipped):
            yield f"{SKIPPED} {result.source}{named}: {result.reason}"
            continue
        ids = ", ".join(map(str, result.rule.event_ids))
        where = _where(analysis.config_source, result.lines)
        yield (
            f"{result.verdict} {result.rule.source}{named} {result.rule.category} ({ids}): "
            f"{result.reason}{where}"
        )


def counted(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def summary_line(analysis: Analysis) -> str:
    found = counts(analysis.results, analysis.samples is not None)
    total = ", ".join(f"{count} {verdict}" for verdict, count in found.items())
    return f"{counted(len(analysis.results), 'rule')}: {total}"


def _example(example: Example | None) -> dict[str, object] | None:
    if example is None:
        return None
    return {"event_id": example.event_id, "fields": dict(example.fields)}


def _finding(finding: Finding) -> dict[str, object]:
    return {
        "event_id": finding.event_id,
        "verdict": str(finding.verdict),
        "reason": finding.reason,
        "lines": list(finding.lines),
        "example": _example(finding.example),
    }


def _recorded(item: Recorded) -> dict[str, object]:
    return {
        "source": item.source,
        "event_id": item.event_id,
        "reason": item.reason,
        "lines": list(item.lines),
    }


def _branch(branch: BranchProof) -> dict[str, object]:
    return {
        "label": branch.label,
        "verdict": str(branch.verdict),
        "findings": [_finding(finding) for finding in branch.findings],
    }


def _entry(result: Result) -> dict[str, object]:
    if isinstance(result, Skipped):
        return {
            "verdict": SKIPPED,
            "source": result.source,
            "title": result.title,
            "reason": result.reason,
        }
    rule = result.rule
    return {
        "verdict": str(result.verdict),
        "source": rule.source,
        "title": rule.title,
        "id": rule.rule_id,
        "category": rule.category,
        "event_ids": list(rule.event_ids),
        "tags": list(rule.tags),
        "reason": result.reason,
        "lines": list(result.lines),
        "example": _example(result.example),
        "branches": [_branch(branch) for branch in result.branches],
        "recorded": [_recorded(item) for item in result.recorded],
    }


def json_document(analysis: Analysis) -> str:
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "sigma-blindspot", "version": analysis.version},
        "config": {"source": analysis.config_source, "sha256": analysis.config_sha256},
        "samples": analysis.samples,
        "summary": counts(analysis.results, analysis.samples is not None),
        "results": [_entry(result) for result in ordered(analysis.results)],
    }
    return json.dumps(document, indent=2, ensure_ascii=True)
