import json
import re
from collections.abc import Iterable, Sequence
from typing import Final

from sigma_blindspot.prover.prove import Proof, Verdict
from sigma_blindspot.report.analysis import Analysis, Result

LAYER_VERSION: Final = "4.5"
NAVIGATOR_VERSION: Final = "5.3.2"
_TECHNIQUE: Final = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_COLOR: Final = "#ff6666"


def techniques(tags: Iterable[str]) -> tuple[str, ...]:
    found = (_TECHNIQUE.fullmatch(tag) for tag in tags)
    return tuple(dict.fromkeys(match.group(1).upper() for match in found if match))


def blind_techniques(results: Sequence[Result]) -> dict[str, list[Proof]]:
    rules: dict[str, list[Proof]] = {}
    for result in results:
        if isinstance(result, Proof):
            for technique in techniques(result.rule.tags):
                rules.setdefault(technique, []).append(result)
    return {
        technique: sorted(proofs, key=lambda proof: proof.rule.source)
        for technique, proofs in sorted(rules.items())
        if all(proof.verdict is Verdict.BLIND for proof in proofs)
    }


def _comment(count: int) -> str:
    return (
        "The only analysed rule is BLIND" if count == 1 else f"All {count} analysed rules are BLIND"
    )


def _technique(technique: str, proofs: Sequence[Proof]) -> dict[str, object]:
    return {
        "techniqueID": technique,
        "color": _COLOR,
        "comment": _comment(len(proofs)),
        "metadata": [{"name": proof.rule.title, "value": proof.rule.source} for proof in proofs],
    }


def layer_document(analysis: Analysis) -> str:
    description = (
        f"ATT&CK techniques whose analysed Sigma rules are all BLIND under "
        f"{analysis.config_source} (SHA-256 {analysis.config_sha256}), from sigma-blindspot "
        f"{analysis.version}."
    )
    document = {
        "name": "sigma-blindspot: blind techniques",
        "versions": {"layer": LAYER_VERSION, "navigator": NAVIGATOR_VERSION},
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Windows"]},
        "layout": {"expandedSubtechniques": "annotated"},
        "techniques": [
            _technique(technique, proofs)
            for technique, proofs in blind_techniques(analysis.results).items()
        ],
        "legendItems": [{"label": "Every analysed rule is BLIND", "color": _COLOR}],
    }
    return json.dumps(document, indent=2, ensure_ascii=True)
