import re
from pathlib import Path

from sigma_blindspot.sysmon.semantics import Semantic, Status

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "src" / "sigma_blindspot"
HEADING = "## Sysmon semantics implemented"


def readme_rows() -> list[tuple[str, ...]]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split(HEADING, 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")][2:]
    return [tuple(cell.strip() for cell in row.strip("|").split("|")) for row in rows]


def marked_semantics() -> set[str]:
    code = "\n".join(
        path.read_text(encoding="utf-8")
        for path in SOURCES.rglob("*.py")
        if path.name != "semantics.py"
    )
    return set(re.findall(r"\bSemantic\.([A-Z_]+)\b", code))


def test_readme_table_matches_the_semantics_registry() -> None:
    expected = [(semantic.behaviour, semantic.status.value) for semantic in Semantic]
    table = "\n".join(f"| {behaviour} | {status} |" for behaviour, status in expected)
    assert readme_rows() == expected, f"README table must list, in order:\n{table}"


def test_every_assumption_is_marked_in_the_code() -> None:
    assumed = {semantic.name for semantic in Semantic if semantic.status is not Status.DOCUMENTED}
    assert assumed <= marked_semantics()


def test_only_assumptions_are_marked_in_the_code() -> None:
    documented = {semantic.name for semantic in Semantic if semantic.status is Status.DOCUMENTED}
    assert marked_semantics().isdisjoint(documented)
