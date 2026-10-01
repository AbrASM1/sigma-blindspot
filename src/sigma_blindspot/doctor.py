import platform
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from typing import Final

_SIGMA_RULE: Final = """\
title: doctor
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
"""


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    version: str | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def check_distribution(name: str, probe: Callable[[], None]) -> Check:
    try:
        version = metadata.version(name)
    except metadata.PackageNotFoundError:
        return Check(name, None, "not installed")
    try:
        probe()
    except Exception as error:
        return Check(name, version, f"{type(error).__name__}: {error}")
    return Check(name, version)


def _probe_pysigma() -> None:
    from sigma.rule import SigmaRule

    for condition in SigmaRule.from_yaml(_SIGMA_RULE).detection.parsed_condition:
        condition.parse()


def _probe_z3() -> None:
    import z3

    solver = z3.Solver()
    solver.set(timeout=5000)
    image = z3.String("image")
    solver.add(z3.SuffixOf(z3.StringVal("\\cmd.exe"), image), z3.Length(image) < 20)
    if solver.check() != z3.sat:
        raise RuntimeError("Z3 cannot solve a basic string constraint")


def run_checks() -> tuple[Check, ...]:
    return (
        Check("python", f"{platform.python_version()} ({platform.platform()})"),
        check_distribution("pysigma", _probe_pysigma),
        check_distribution("z3-solver", _probe_z3),
    )
