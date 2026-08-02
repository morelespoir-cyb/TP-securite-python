import pytest

from src.tp2.utils.lib import parse_shellcode, load_shellcode


def test_parse_shellcode_basic():
    assert parse_shellcode(r"\xEB\x54\x8B") == b"\xeb\x54\x8b"


def test_parse_shellcode_case_insensitive():
    assert parse_shellcode(r"\xab\xAB\xaB\xAb") == b"\xab\xab\xab\xab"


def test_parse_shellcode_ignores_whitespace_and_newlines():
    raw = "\\xEB\\x54\n\\x8B \\x75\t\\x3C"
    assert parse_shellcode(raw) == b"\xeb\x54\x8b\x75\x3c"


def test_parse_shellcode_empty_raises():
    with pytest.raises(ValueError):
        parse_shellcode("hello world")


def test_load_shellcode_reads_file(tmp_path):
    p = tmp_path / "sc.txt"
    p.write_text(r"\xDE\xAD\xBE\xEF")
    assert load_shellcode(p) == b"\xde\xad\xbe\xef"