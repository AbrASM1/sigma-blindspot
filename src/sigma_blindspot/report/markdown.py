import re
from collections.abc import Iterator, Sequence
from typing import Final

from sigma_blindspot.prover.prove import Proof, Verdict
from sigma_blindspot.report.analysis import Analysis, Result, counts, ordered

_SPECIAL: Final = re.compile(r"([\\`*_\[\]<>&|~$])")
_BREAKS: Final = re.compile(r"[\r\n]+")
_FAILING: Final = frozenset({Verdict.BLIND, Verdict.PARTIAL})


def escape(text: str) -> str:
    return _SPECIAL.sub(r"\\\1", _BREAKS.sub(" ", text))


def _rules(count: int) -> str:
    return f"{count} rule" if count == 1 else f"{count} rules"


def _groups(proofs: Sequence[Proof]) -> list[tuple[int | None, list[Proof]]]:
    by_line: dict[int | None, list[Proof]] = {}
    for proof in proofs:
        for line in proof.lines or (None,):
            by_line.setdefault(line, []).append(proof)
    return sorted(
        by_line.items(),
        key=lambda item: (item[0] is None, -len(item[1]), item[0] or 0),
    )


def _row(proof: Proof) -> str:
    rule = proof.rule
    ids = ", ".join(map(str, rule.event_ids))
    cells = (
        str(proof.verdict),
        escape(rule.title),
        escape(rule.source),
        escape(f"{rule.category} ({ids})"),
        escape(proof.reason),
    )
    return "| " + " | ".join(cells) + " |"


def _summary(results: Sequence[Result]) -> Iterator[str]:
    yield "| Verdict | Rules |"
    yield "| --- | --- |"
    for verdict, count in counts(results).items():
        yield f"| {verdict} | {count} |"
    yield f"| Total | {len(results)} |"


def markdown_lines(analysis: Analysis) -> Iterator[str]:
    config_source = escape(analysis.config_source)
    yield "# sigma-blindspot analysis"
    yield ""
    yield f"- Configuration: {config_source}"
    yield f"- SHA-256: {analysis.config_sha256}"
    yield f"- sigma-blindspot {escape(analysis.version)}"
    yield ""
    yield from _summary(analysis.results)
    yield ""
    yield "## BLIND and PARTIAL rules by configuration line"
    failing = [
        result
        for result in ordered(analysis.results)
        if isinstance(result, Proof) and result.verdict in _FAILING
    ]
    if not failing:
        yield ""
        yield "None."
    for line, proofs in _groups(failing):
        where = "No configuration line" if line is None else f"{config_source}:{line}"
        yield ""
        yield f"### {where}, {_rules(len(proofs))}"
        yield ""
        yield "| Verdict | Title | Rule | Category | Reason |"
        yield "| --- | --- | --- | --- | --- |"
        yield from map(_row, proofs)
