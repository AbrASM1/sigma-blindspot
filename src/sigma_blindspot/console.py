import re
import sys
from collections.abc import Callable, Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final, TextIO


class ColorMode(StrEnum):
    AUTO = "auto"
    ALWAYS = "always"
    NEVER = "never"


_RESET: Final = "\x1b[0m"
_STYLES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "BLIND": "1;31",
        "MISSED": "1;35",
        "PARTIAL": "33",
        "RULE_UNSAT": "36",
        "UNKNOWN": "90",
        "OK": "32",
        "SKIPPED": "2",
        "LOGGED": "32",
        "DROPPED": "31",
        "FAIL": "1;31",
        "logged": "32",
        "not logged": "31",
        "dropped": "31",
        "unknown": "90",
    }
)
_COUNT: Final = re.compile(r"\b(\d+) ([A-Za-z_]+)\b")
_ENABLE_VIRTUAL_TERMINAL_PROCESSING: Final = 0x0004


def paint(word: str, enabled: bool) -> str:
    style = _STYLES.get(word)
    return f"\x1b[{style}m{word}{_RESET}" if enabled and style else word


def paint_counts(text: str, enabled: bool) -> str:
    def counted(match: re.Match[str]) -> str:
        count, word = match.groups()
        return f"{count} {paint(word, enabled and count != '0')}"

    return _COUNT.sub(counted, text)


def enable_terminal(stream: TextIO) -> bool:
    if sys.platform != "win32":
        return True
    import ctypes
    import msvcrt

    try:
        handle = msvcrt.get_osfhandle(stream.fileno())
    except (AttributeError, OSError, ValueError):
        return False
    mode = ctypes.c_ulong()
    kernel32 = ctypes.windll.kernel32
    if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        return False
    return bool(kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING))


def color_enabled(
    mode: ColorMode,
    stream: TextIO,
    environ: Mapping[str, str],
    enable: Callable[[TextIO], bool] = enable_terminal,
) -> bool:
    if mode is ColorMode.NEVER:
        return False
    if mode is ColorMode.ALWAYS:
        enable(stream)
        return True
    if environ.get("NO_COLOR") or environ.get("TERM") == "dumb":
        return False
    return stream.isatty() and enable(stream)
