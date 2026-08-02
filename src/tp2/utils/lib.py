"""Utility functions for TP2 shellcode analysis."""
import re
from pathlib import Path


def parse_shellcode(raw: str) -> bytes:
    """
    Parse a shellcode string like '\\xEB\\x54\\x8B...' into raw bytes.

    Accepts multi-line input, whitespace, and mixed case. Anything that
    isn't a valid \\xHH sequence is ignored (line breaks, spaces, escape
    doublings, tabs).

    :param raw: string containing '\\xHH' escape sequences
    :return: parsed bytes
    :raises ValueError: if no valid \\xHH sequence is found
    """
    pattern = re.compile(r"\\x([0-9a-fA-F]{2})")
    hex_bytes = pattern.findall(raw)
    if not hex_bytes:
        raise ValueError("No valid '\\xHH' hex sequence found in input")
    return bytes(int(h, 16) for h in hex_bytes)


def load_shellcode(path: str | Path) -> bytes:
    """
    Read a file containing a shellcode as '\\xHH' escape sequences and
    return the raw bytes.

    :param path: path to the shellcode file
    :return: parsed bytes
    """
    content = Path(path).read_text(encoding="utf-8")
    return parse_shellcode(content)