from pathlib import Path

import pytest
from benchmark import blinding_lines, header, summarize
from conftest import line_of
from fetch_configs import CONFIGS
from fetch_sigmahq import COMMIT

from sigma_blindspot.prover.prove import Prover
from sigma_blindspot.report.analysis import Result
from sigma_blindspot.report.markdown import escape
from sigma_blindspot.sigma.ir import LoadedRule
from sigma_blindspot.sigma.loader import load_rules
from sigma_blindspot.sysmon.parser import load_config

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = FIXTURES / "sysmon.xml"
TEXT = CONFIG.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def results() -> list[Result]:
    prover = Prover(load_config(CONFIG))
    loaded = load_rules([FIXTURES / "rules"])
    return [prover.prove(item) if isinstance(item, LoadedRule) else item for item in loaded]


def test_blinding_lines_rank_config_lines_and_skip_rules_without_one(
    results: list[Result],
) -> None:
    assert blinding_lines(results) == [
        (line_of(TEXT, needle), 1)
        for needle in ("svchost.exe", "ccmexec.exe", "<NetworkConnect", "<FileCreate")
    ]


def test_summary_counts_verdicts_and_shows_the_blinding_elements(results: list[Result]) -> None:
    lines = summarize("fixture", TEXT, results, 1.4).splitlines()
    assert lines[:3] == ["## fixture", "", "10 rules analysed in 1 s."]
    assert "| BLIND | 5 |" in lines
    element = escape('<ParentImage condition="end with">\\ccmexec.exe</ParentImage>')
    assert f"| {line_of(TEXT, 'ccmexec.exe')} | 1 | {element} |" in lines


@pytest.mark.parametrize("ending", ["\r\n", "\r"])
def test_summary_counts_lines_like_the_xml_parser(results: list[Result], ending: str) -> None:
    expected = summarize("fixture", TEXT, results, 0)
    assert summarize("fixture", TEXT.replace("\n", ending), results, 0) == expected


def test_header_states_versions_sources_and_method() -> None:
    text = header(2000, 4)
    assert f"`{COMMIT}`" in text
    assert all(config.url in text and config.sha256 in text for config in CONFIGS)
    assert "4 worker processes, 2000 ms per Z3 check" in text
    assert "what it accepts not to see" in text
