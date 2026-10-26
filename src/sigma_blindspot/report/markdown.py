import re
from collections.abc import Iterator, Sequence
from typing import Final

from sigma_blindspot.prover.prove import Proof
from sigma_blindspot.report.analysis import (
    FAILING,
    Analysis,
    Result,
    counts,
    rules_by_line,
    shown,
)

_SPECIAL: Final = re.compile(r"([\\`*_\[\]<>&|~$])")
_BREAKS: Final = re.compile(r"[\r\n]+")


def escape(text: str) -> str:
    return _SPECIAL.sub(r"\\\1", _BREAKS.sub(" ", text))


def _rules(count: int) -> str:
    return f"{count} rule" if count == 1 else f"{count} rules"


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


def _listed(names: Sequence[str]) -> str:
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


def _summary(results: Sequence[Result], samples: bool) -> Iterator[str]:
    yield "| Verdict | Rules |"
    yield "| --- | --- |"
    for verdict, count in counts(results, samples).items():
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
    samples = analysis.samples is not None
    failing = [verdict for verdict in shown(samples) if verdict in FAILING]
    yield from _summary(analysis.results, samples)
    yield ""
    yield f"## {_listed(failing)} rules by configuration line"
    groups = rules_by_line(analysis.results)
    if not groups:
        yield ""
        yield "None."
    for line, proofs in groups:
        where = "No configuration line" if line is None else f"{config_source}:{line}"
        yield ""
        yield f"### {where}, {_rules(len(proofs))}"
        yield ""
        yield "| Verdict | Title | Rule | Category | Reason |"
        yield "| --- | --- | --- | --- | --- |"
        yield from map(_row, proofs)
