import hashlib
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
TARGET: Final = ROOT / ".cache" / "configs"
_GITHUB: Final = "https://raw.githubusercontent.com"
_MODULAR: Final = (
    "https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43"
)


@dataclass(frozen=True, slots=True)
class Config:
    name: str
    url: str
    sha256: str


CONFIGS: Final = (
    Config(
        "swiftonsecurity",
        f"{_GITHUB}/SwiftOnSecurity/sysmon-config/1836897f12fbd6a0a473665ef6abc34a6b497e31/"
        "sysmonconfig-export.xml",
        "055febc600e6d7448cdf3812307275912927a62b1f94d0d933b64b294bc87162",
    ),
    Config(
        "neo23x0",
        f"{_GITHUB}/Neo23x0/sysmon-config/cfe23bfa6197adfb0c76a4a644fab2f82a5f562f/"
        "sysmonconfig-export.xml",
        "4e93c0667a95f696700c9ff266cb7dd1310861c82133e1056737b9d1ca8d3f1c",
    ),
    Config(
        "neo23x0-block",
        f"{_GITHUB}/Neo23x0/sysmon-config/cfe23bfa6197adfb0c76a4a644fab2f82a5f562f/"
        "sysmonconfig-export-block.xml",
        "9c4719f15aabee3f36cc624c11ff2fb55738436a30b1ec1990f7e366c8f73354",
    ),
    Config(
        "sysmon-modular",
        f"{_MODULAR}/sysmonconfig.xml",
        "64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e",
    ),
    Config(
        "sysmon-modular-excludes-only",
        f"{_MODULAR}/sysmonconfig-excludes-only.xml",
        "4c7d27bc2847f7de816ddde90e7de37d5b9473461b27424882e9b93f00cd28a4",
    ),
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_config(config: Config, target: Path = TARGET) -> Path:
    path = target / f"{config.name}.xml"
    if path.exists() and _sha256(path.read_bytes()) == config.sha256:
        return path
    with urllib.request.urlopen(config.url, timeout=120) as response:
        data = response.read()
    if _sha256(data) != config.sha256:
        raise RuntimeError(f"{config.name}: SHA-256 {_sha256(data)} is not the pinned one")
    target.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def fetch_configs(target: Path = TARGET) -> dict[str, Path]:
    return {config.name: fetch_config(config, target) for config in CONFIGS}


def main() -> int:
    for name, path in fetch_configs().items():
        sys.stdout.write(f"{name}: {path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
