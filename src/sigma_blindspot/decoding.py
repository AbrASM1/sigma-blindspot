import codecs
from typing import Final

from sigma_blindspot.errors import SourceError

_BYTE_ORDER_MARKS: Final = (
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def decode_text(data: bytes, source: str, error: type[SourceError]) -> str:
    mark, codec = next(
        ((mark, codec) for mark, codec in _BYTE_ORDER_MARKS if data.startswith(mark)),
        (b"", "utf-8"),
    )
    body = data[len(mark) :]
    try:
        return body.decode(codec)
    except UnicodeDecodeError as cause:
        line = body[: cause.start].decode(codec).count("\n") + 1
        raise error(f"not valid {codec}: {cause.reason}", line, source) from cause
