import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def tracked_files() -> list[Path]:
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode()
    return [ROOT / name for name in listed.split("\0") if name]


def test_tracked_files_are_utf8_without_hidden_characters() -> None:
    hidden = [
        f"{path.relative_to(ROOT)}:{number}: {character!r}"
        for path in tracked_files()
        for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1)
        for character in line
        if not character.isprintable()
    ]
    assert hidden == []
