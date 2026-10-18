import subprocess
import sys
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
REPOSITORY: Final = "https://github.com/SigmaHQ/sigma.git"
COMMIT: Final = "b7920ed31356fb7f6a9275b34737d8604c65bac3"
PATHS: Final = ("/rules/windows/", "/regression_data/")
TARGET: Final = ROOT / ".cache" / "sigmahq"


def _git(target: Path, *arguments: str, check: bool = True) -> str:
    done = subprocess.run(
        ["git", *arguments], cwd=target, check=check, capture_output=True, text=True
    )
    return done.stdout.strip()


def fetch_sigmahq(target: Path = TARGET) -> Path:
    if not (target / ".git").exists():
        target.mkdir(parents=True, exist_ok=True)
        _git(target, "init", "--quiet")
        _git(target, "remote", "add", "origin", REPOSITORY)
        _git(target, "sparse-checkout", "set", "--no-cone", *PATHS)
    if _git(target, "rev-parse", "--verify", "--quiet", "HEAD", check=False) != COMMIT:
        _git(target, "fetch", "--quiet", "--depth", "1", "--filter=blob:none", "origin", COMMIT)
        _git(target, "checkout", "--quiet", "--detach", "FETCH_HEAD")
    return target


def main() -> int:
    sys.stdout.write(f"SigmaHQ {COMMIT} in {fetch_sigmahq()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
