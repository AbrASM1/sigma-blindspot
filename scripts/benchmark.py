import argparse
import os
import platform
import re
import sys
import time
from collections.abc import Sequence
from importlib import metadata
from pathlib import Path
from typing import Final

from fetch_configs import CONFIGS, fetch_configs
from fetch_sigmahq import COMMIT, fetch_sigmahq

from sigma_blindspot.decoding import decode_text
from sigma_blindspot.errors import ConfigError
from sigma_blindspot.prover.prove import DEFAULT_TIMEOUT_MS
from sigma_blindspot.report.analysis import Result, counts, rules_by_line
from sigma_blindspot.report.markdown import escape
from sigma_blindspot.runner import prove_all
from sigma_blindspot.sigma.ir import LoadedRule, Skipped
from sigma_blindspot.sigma.loader import load_rules
from sigma_blindspot.sysmon.parser import parse_config

ROOT: Final = Path(__file__).resolve().parents[1]
OUTPUT: Final = ROOT / "bench" / "results.md"
TOP: Final = 10
_LINE_BREAK: Final = re.compile(r"\r\n?|\n")


def blinding_lines(results: Sequence[Result]) -> list[tuple[int, int]]:
    found = ((line, len(proofs)) for line, proofs in rules_by_line(results))
    return [(line, count) for line, count in found if line is not None][:TOP]


def summarize(name: str, config_text: str, results: Sequence[Result], seconds: float) -> str:
    source = _LINE_BREAK.split(config_text)
    rows = [f"| {verdict} | {count} |" for verdict, count in counts(results).items()]
    lines = [
        f"| {line} | {rules} | {escape(source[line - 1].strip())} |"
        for line, rules in blinding_lines(results)
    ]
    unfiltered = len(dict(rules_by_line(results)).get(None, []))
    return "\n".join(
        [
            f"## {name}",
            "",
            f"{len(results)} rules analysed in {seconds:.0f} s.",
            "",
            "| Verdict | Rules |",
            "| --- | --- |",
            *rows,
            "",
            "Configuration lines that make the most rules `BLIND` or `PARTIAL`:",
            "",
            "| Line | Rules | Element |",
            "| --- | --- | --- |",
            *lines,
            "",
            f"Rules `BLIND` or `PARTIAL` without a configuration line, because their event type"
            f" has no filter and is not logged without one: {unfiltered}.",
            "",
        ]
    )


def header(timeout_ms: int, jobs: int) -> str:
    versions = ", ".join(
        f"{name} {metadata.version(name)}" for name in ("sigma-blindspot", "pysigma", "z3-solver")
    )
    sources = "\n".join(
        f"- `{config.name}`: {config.url} (SHA-256 `{config.sha256}`)" for config in CONFIGS
    )
    return "\n".join(
        [
            "# Benchmark",
            "",
            f"{versions}, Python {platform.python_version()} on {platform.platform()},"
            f" {jobs} worker processes, {timeout_ms} ms per Z3 check.",
            "",
            f"Rules: SigmaHQ `rules/windows` at commit `{COMMIT}`. Configurations:",
            "",
            sources,
            "",
            "Method: `analyze` on every configuration with the same rules. A `BLIND` rule can",
            "never fire because of what the configuration does not log. For an include-only",
            "configuration, that is what it accepts not to see to reduce noise, not a defect.",
            "`UNKNOWN` covers unsupported Sigma constructs, Sysmon defaults not verified by a lab",
            "probe, and Z3 timeouts. Every assumption is listed in `docs/reference.md`.",
            "",
            "`BLIND` is a proof; `OK` is not a guarantee that real attacks are logged: it only",
            "means that Z3 found one event that matches the rule and is logged. What Sysmon logs",
            "for an event type without a filter comes from lab probes on Sysmon 15.22",
            "(`lab/results/`) and may differ on other versions.",
            "",
        ]
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark popular Sysmon configs on SigmaHQ.")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    arguments = parser.parse_args(argv)
    loaded = load_rules([fetch_sigmahq() / "rules" / "windows"])
    rules = [item for item in loaded if isinstance(item, LoadedRule)]
    skipped = [item for item in loaded if isinstance(item, Skipped)]
    sections = [header(arguments.timeout_ms, arguments.jobs)]
    for name, path in fetch_configs().items():
        data = path.read_bytes()
        config = parse_config(data, path.name)
        started = time.monotonic()
        proofs = prove_all(config, data, rules, arguments.timeout_ms, arguments.jobs)
        seconds = time.monotonic() - started
        text = decode_text(data, path.name, ConfigError)
        sections.append(summarize(name, text, [*proofs, *skipped], seconds))
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text("\n".join(sections), encoding="utf-8")
    sys.stdout.write(f"report written to {arguments.output}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
