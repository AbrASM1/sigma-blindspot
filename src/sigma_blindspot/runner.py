from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ProcessPoolExecutor
from typing import Final

from sigma_blindspot.prover.prove import Proof, Prover
from sigma_blindspot.sigma.ir import LoadedRule
from sigma_blindspot.sysmon.model import SysmonConfig
from sigma_blindspot.sysmon.parser import parse_config

RULES_PER_WORKER: Final = 50

type Progress = Callable[[int], None]

_worker: Prover | None = None


def _start(data: bytes, source: str, timeout_ms: int) -> None:
    global _worker
    _worker = Prover(parse_config(data, source), timeout_ms)


def _prove(rule: LoadedRule) -> Proof:
    if _worker is None:
        raise RuntimeError("the worker was not started")
    return _worker.prove(rule)


def auto_jobs(rules: int, processors: int | None) -> int:
    return max(1, min(processors or 1, rules // RULES_PER_WORKER))


def _collect(proofs: Iterable[Proof], progress: Progress | None) -> tuple[Proof, ...]:
    collected: list[Proof] = []
    for proof in proofs:
        collected.append(proof)
        if progress is not None:
            progress(len(collected))
    return tuple(collected)


def prove_all(
    config: SysmonConfig,
    data: bytes,
    rules: Sequence[LoadedRule],
    timeout_ms: int,
    jobs: int,
    *,
    progress: Progress | None = None,
) -> tuple[Proof, ...]:
    if jobs == 1 or len(rules) < 2:
        prover = Prover(config, timeout_ms)
        return _collect(map(prover.prove, rules), progress)
    chunk = max(1, len(rules) // (jobs * 8))
    with ProcessPoolExecutor(
        jobs, initializer=_start, initargs=(data, config.source, timeout_ms)
    ) as pool:
        return _collect(pool.map(_prove, rules, chunksize=chunk), progress)
