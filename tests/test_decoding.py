import pytest
from hypothesis import given
from hypothesis import strategies as st
from strategies import encode, encodings

from sigma_blindspot.decoding import decode_text
from sigma_blindspot.errors import ConfigError

SOURCE = "file.txt"


@given(text=st.text().filter(lambda text: not text.startswith("﻿")), encoding=encodings)
def test_decodes_utf8_and_utf16_with_byte_order_marks(text: str, encoding: str) -> None:
    assert decode_text(encode(text, encoding), SOURCE, ConfigError) == text


@pytest.mark.parametrize(
    ("data", "codec", "line"),
    [
        (b"a\nb\n\xff\n", "utf-8", 3),
        (b"\xef\xbb\xbfa\r\n\xc3", "utf-8", 2),
        (b"\xff\xfe" + "a\nb\n".encode("utf-16-le") + b"\x00", "utf-16-le", 3),
        (b"\xfe\xff" + "\n".encode("utf-16-be") + b"\xdc\x00", "utf-16-be", 2),
    ],
)
def test_reports_the_line_of_the_first_undecodable_byte(data: bytes, codec: str, line: int) -> None:
    with pytest.raises(ConfigError) as caught:
        decode_text(data, SOURCE, ConfigError)
    assert (caught.value.source, caught.value.line) == (SOURCE, line)
    assert caught.value.message.startswith(f"not valid {codec}: ")
