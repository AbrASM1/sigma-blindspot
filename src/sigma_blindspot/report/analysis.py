import json
from collections import Counter
from collections.abc import Iterator, Sequence
from typing import Final

from sigma_blindspot.prover.prove import BranchProof, Example, Finding, Proof, Verdict
from sigma_blindspot.sigma.ir import Skipped
from sigma_blindspot.sysmon.model import Lines

type Result = Proof | Skipped

SCHEMA_VERSION: Final = 1
SKIPPED: Final = "SKIPPED"
ORDER: Final = (
    Verdict.BLIND,
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


def counts(results: Sequence[Result]) -> dict[str, int]:
    found = Counter(map(verdict_of, results))
    return {str(verdict): found[verdict] for verdict in ORDER}


def _where(config_source: str, lines: Lines) -> str:
    places = ", ".join(f"{config_source}:{line}" for line in lines)
    return f" ({places})" if places else ""


def text_lines(config_source: str, results: Sequence[Result]) -> Iterator[str]:
    for result in ordered(results):
        title = _title(result)
        named = "" if title is None else f" {json.dumps(title)}"
        if isinstance(result, Skipped):
            yield f"{SKIPPED} {result.source}{named}: {result.reason}"
            continue
        ids = ", ".join(map(str, result.rule.event_ids))
        where = _where(config_source, result.lines)
        yield (
            f"{result.verdict} {result.rule.source}{named} {result.rule.category} ({ids}): "
            f"{result.reason}{where}"
        )
    total = ", ".join(f"{count} {verdict}" for verdict, count in counts(results).items())
    yield f"{len(results)} rules: {total}"


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
    }


def json_document(
    version: str, config_source: str, config_sha256: str, results: Sequence[Result]
) -> str:
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "sigma-blindspot", "version": version},
        "config": {"source": config_source, "sha256": config_sha256},
        "summary": counts(results),
        "results": [_entry(result) for result in ordered(results)],
    }
    return json.dumps(document, indent=2, ensure_ascii=True)
