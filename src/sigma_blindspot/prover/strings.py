import re
from typing import Any, Final

import z3

MAX_CHAR: Final = 0x2FFFF
_PLAIN: Final = frozenset(map(chr, range(0x20, 0x7F))) - {"\\"}
_ESCAPE: Final = re.compile(r"\\u\{([0-9a-fA-F]+)\}")


class Unrepresentable(ValueError):
    pass


def _escape(character: str) -> str:
    if character in _PLAIN:
        return character
    if ord(character) > MAX_CHAR:
        raise Unrepresentable(f"U+{ord(character):X} is beyond the characters Z3 represents")
    return f"\\u{{{ord(character):x}}}"


def lit(text: str, context: Any = None) -> Any:
    return z3.StringVal("".join(map(_escape, text)), context)


def read(value: Any) -> str:
    text: str = value.as_string()
    return _ESCAPE.sub(lambda escape: chr(int(escape.group(1), 16)), text)
