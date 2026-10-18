import json
from pathlib import Path

import pytest

from sigma_blindspot.sysmon.jsonl import parse_events
from sigma_blindspot.sysmon.parser import parse_config

LAB = Path(__file__).resolve().parents[1] / "lab"
PROBES = sorted(path for path in (LAB / "probes").iterdir() if path.is_dir())
MARKER = "sbprobe0123456789ab"


def marked(path: Path) -> bytes:
    return path.read_text(encoding="utf-8").replace("MARKER", MARKER).encode()


def test_every_probe_is_listed_in_the_lab_readme() -> None:
    readme = (LAB / "README.md").read_text(encoding="utf-8")
    assert PROBES and all(f"`{probe.name}`" in readme for probe in PROBES)


@pytest.mark.parametrize("probe", PROBES, ids=lambda probe: probe.name)
def test_probes_have_a_valid_config_and_expected_events(probe: Path) -> None:
    names = {path.name for path in probe.iterdir()}
    assert names == {"README.md", "config.xml", "expected.jsonl", "trigger.ps1"}
    parse_config(marked(probe / "config.xml"), "config.xml")
    events = parse_events(marked(probe / "expected.jsonl"), "expected.jsonl")
    lines = [json.loads(line) for line in marked(probe / "expected.jsonl").splitlines() if line]
    assert len(events) == len(lines) > 0
    assert all(line["ProbeKey"] == "PID" or MARKER in line["ProbeKey"] for line in lines)
