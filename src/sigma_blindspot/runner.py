from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor

from sigma_blindspot.prover.prove import Proof, Prover
from sigma_blindspot.sigma.ir import LoadedRule
from sigma_blindspot.sysmon.model import SysmonConfig
from sigma_blindspot.sysmon.parser import parse_config

_worker: Prover | None = None


def _start(data: bytes, source: str, timeout_ms: int) -> None:
    global _worker
    _worker = Prover(parse_config(data, source), timeout_ms)


def _prove(rule: LoadedRule) -> Proof:
    if _worker is None:
        raise RuntimeError("the worker was not started")
    return _worker.prove(rule)


def prove_all(
    config: SysmonConfig,
    data: bytes,
    rules: Sequence[LoadedRule],
    timeout_ms: int,
    jobs: int,
) -> tuple[Proof, ...]:
    if jobs == 1 or len(rules) < 2:
        prover = Prover(config, timeout_ms)
        return tuple(map(prover.prove, rules))
    chunk = max(1, len(rules) // (jobs * 8))
    with ProcessPoolExecutor(
        jobs, initializer=_start, initargs=(data, config.source, timeout_ms)
    ) as pool:
        return tuple(pool.map(_prove, rules, chunksize=chunk))
