import json
from dataclasses import replace
from pathlib import Path

import pytest
import validate_regression
from validate_regression import validate

from sigma_blindspot.prover.prove import Proof, Prover, Verdict
from sigma_blindspot.sigma.ir import LoadedRule
from sigma_blindspot.sysmon.evtx_json import SYSMON_PROVIDER
from sigma_blindspot.sysmon.model import SysmonConfig
from sigma_blindspot.sysmon.parser import load_config, parse_config

FIXTURES = Path(__file__).parent / "fixtures"
RULE = FIXTURES / "rules" / "process_ccmexec_child.yml"
RULE_ID = "7e3a9b1c-2d4f-4e6a-8b0c-1d2e3f4a5b62"
SCCM = "C:\\Windows\\CCM\\CcmExec.exe"
EVERYTHING = (
    b'<Sysmon schemaversion="4.90"><EventFiltering>'
    b'<ProcessCreate onmatch="exclude"/></EventFiltering></Sysmon>'
)


def configs() -> dict[str, SysmonConfig]:
    return {
        "fixture": load_config(FIXTURES / "sysmon.xml"),
        "everything": parse_config(EVERYTHING, "everything.xml"),
    }


def exported(parent: str) -> dict[str, object]:
    system = {"Provider": {"#attributes": {"Name": SYSMON_PROVIDER}}, "EventID": 1}
    data = {"Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": parent}
    return {"Event": {"System": system, "EventData": data}}


def sigmahq(root: Path, match_count: int | None, *parents: str) -> Path:
    rules = root / "rules" / "windows" / "process_creation"
    rules.mkdir(parents=True)
    (rules / RULE.name).write_bytes(RULE.read_bytes())
    data = root / "regression_data" / "rules" / "windows" / "process_creation" / RULE.stem
    data.mkdir(parents=True)
    sample = data / f"{RULE_ID}.evtx"
    test: dict[str, object] = {
        "name": "Positive Detection Test",
        "type": "evtx",
        "provider": SYSMON_PROVIDER,
        "path": sample.relative_to(root).as_posix(),
    }
    if match_count is not None:
        test["match_count"] = match_count
    info = {"rule_metadata": [{"id": RULE_ID}], "regression_tests_info": [test]}
    (data / "info.yml").write_text(json.dumps(info), encoding="utf-8")
    documents = "\n".join(json.dumps(exported(parent)) for parent in parents)
    sample.with_suffix(".json").write_text(documents, encoding="utf-8")
    return root


def test_samples_dropped_by_the_config_agree_with_the_prover(tmp_path: Path) -> None:
    counts, mismatches = validate(sigmahq(tmp_path, None, SCCM), configs())
    assert mismatches == []
    assert dict(counts) == {
        "samples checked": 1,
        "branches pinned to a sample": 1,
        "samples logged by everything": 1,
    }


def test_fewer_matches_than_sigmahq_expects_is_a_mismatch(tmp_path: Path) -> None:
    root = sigmahq(tmp_path, 2, SCCM, "C:\\Windows\\explorer.exe")
    _, mismatches = validate(root, configs())
    assert [item.check for item in mismatches] == ["1 evaluator"]
    assert "matches 1 event, SigmaHQ expects at least 2" in mismatches[0].detail


def test_an_undecided_encoding_is_a_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(validate_regression, "pinned_satisfiable", lambda condition, event: None)
    _, mismatches = validate(sigmahq(tmp_path, None, SCCM), configs())
    assert [item.check for item in mismatches] == ["2 encoding"]


def test_a_rule_proven_blind_on_a_logged_sample_is_a_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prove = Prover.prove

    def blind(self: Prover, rule: LoadedRule) -> Proof:
        proof = prove(self, rule)
        branches = tuple(
            replace(
                branch,
                findings=tuple(
                    replace(finding, verdict=Verdict.BLIND) for finding in branch.findings
                ),
            )
            for branch in proof.branches
        )
        return replace(proof, verdict=Verdict.BLIND, branches=branches)

    monkeypatch.setattr(Prover, "prove", blind)
    _, mismatches = validate(sigmahq(tmp_path, None, SCCM), configs())
    assert [item.check for item in mismatches] == ["3 prover"]
    assert mismatches[0].detail.startswith("everything logs the sample, the prover says BLIND")
