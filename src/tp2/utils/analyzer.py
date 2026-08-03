"""Shellcode analyzers: strings, capstone, pylibemu, LLM."""
import re


# Minimum length for a candidate string to be considered "interesting"
DEFAULT_MIN_LENGTH = 4


def get_shellcode_strings(
    shellcode: bytes,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> dict[str, list[str]]:
    """
    Extract printable ASCII and UTF-16LE strings from a shellcode blob.

    Mirrors the Unix `strings` command with both ASCII and wide-string
    scanning. UTF-16LE is important on Windows shellcodes where API
    argument strings are commonly wide-encoded.

    Only strings of `min_length` characters or more are returned, to
    filter out noise from opcodes that happen to look printable.

    :param shellcode: raw shellcode bytes
    :param min_length: minimum length for a string to be reported
    :return: dict with keys 'ascii' and 'utf16le', each mapping to a
             list of extracted strings (ordered by appearance)
    """
    return {
        "ascii": _extract_ascii(shellcode, min_length),
        "utf16le": _extract_utf16le(shellcode, min_length),
    }


def _extract_ascii(data: bytes, min_length: int) -> list[str]:
    """
    Scan for runs of printable ASCII bytes (0x20–0x7E, plus tab/newline)
    and return those meeting the minimum length threshold.
    """
    pattern = rb"[\x20-\x7e\t]{" + str(min_length).encode() + rb",}"
    return [m.decode("ascii") for m in re.findall(pattern, data)]


def _extract_utf16le(data: bytes, min_length: int) -> list[str]:
    """
    Scan for UTF-16LE runs (printable ASCII char followed by null byte)
    and return decoded strings meeting the minimum length threshold.

    Simple heuristic that catches most Windows wide-strings without a
    full UTF-16 codec pass.
    """
    # (printable byte + null byte) repeated
    pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
    matches = re.findall(pattern, data)
    return [m.decode("utf-16le") for m in matches]