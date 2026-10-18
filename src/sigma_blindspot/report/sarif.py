import json
from pathlib import Path
from typing import Final
from urllib.parse import quote

from sigma_blindspot.prover.prove import Proof, Verdict
from sigma_blindspot.report.analysis import Analysis, ordered
from sigma_blindspot.sysmon.model import Lines

SARIF_VERSION: Final = "2.1.0"
SCHEMA: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
_RULE_INDEX: Final = {Verdict.BLIND: 0, Verdict.PARTIAL: 1}
_RULES: Final = (
    {
        "id": str(Verdict.BLIND),
        "name": "BlindSigmaRule",
        "shortDescription": {
            "text": "The Sigma rule can never fire under the Sysmon configuration."
        },
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": str(Verdict.PARTIAL),
        "name": "PartlyBlindSigmaRule",
        "shortDescription": {
            "text": "Top-level branches of the Sigma rule can never fire under the Sysmon "
            "configuration."
        },
        "defaultConfiguration": {"level": "warning"},
    },
)


def artifact_uri(source: str) -> str:
    path = Path(source)
    return path.as_uri() if path.is_absolute() else quote(path.as_posix())


def _location(uri: str, line: int | None) -> dict[str, object]:
    physical: dict[str, object] = {"artifactLocation": {"uri": uri}}
    if line is not None:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def _message(proof: Proof) -> str:
    title = json.dumps(proof.rule.title, ensure_ascii=False)
    if proof.verdict is Verdict.PARTIAL:
        blind = ", ".join(
            branch.label for branch in proof.branches if branch.verdict is Verdict.BLIND
        )
        return f"Some branches of Sigma rule {title} can never fire: {blind}."
    return f"Sigma rule {title} can never fire: {proof.reason}."


def _related(proof: Proof, config_uri: str, others: Lines) -> list[dict[str, object]]:
    rule = {**_location(artifact_uri(proof.rule.source), None), "message": {"text": "Sigma rule"}}
    lines = [
        {**_location(config_uri, line), "message": {"text": "Also responsible"}} for line in others
    ]
    return [{"id": index, **location} for index, location in enumerate([rule, *lines], start=1)]


def _result(proof: Proof, config_uri: str) -> dict[str, object]:
    primary = proof.lines[0] if proof.lines else None
    return {
        "ruleId": str(proof.verdict),
        "ruleIndex": _RULE_INDEX[proof.verdict],
        "level": "warning",
        "message": {"text": _message(proof)},
        "locations": [_location(config_uri, primary)],
        "relatedLocations": _related(proof, config_uri, proof.lines[1:]),
        "properties": {"tags": list(proof.rule.tags)},
    }


def sarif_document(analysis: Analysis) -> str:
    config_uri = artifact_uri(analysis.config_source)
    failing = [
        result
        for result in ordered(analysis.results)
        if isinstance(result, Proof) and result.verdict in _RULE_INDEX
    ]
    driver = {"name": "sigma-blindspot", "version": analysis.version, "rules": _RULES}
    artifact = {"location": {"uri": config_uri}, "hashes": {"sha-256": analysis.config_sha256}}
    run = {
        "tool": {"driver": driver},
        "artifacts": [artifact],
        "results": [_result(proof, config_uri) for proof in failing],
    }
    document = {"$schema": SCHEMA, "version": SARIF_VERSION, "runs": [run]}
    return json.dumps(document, indent=2, ensure_ascii=True)
