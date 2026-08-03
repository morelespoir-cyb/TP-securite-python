from src.tp2.utils.analyzer import (
    get_shellcode_strings,
    _extract_ascii,
    _extract_utf16le,
    DEFAULT_MIN_LENGTH,
)


# ---------- _extract_ascii ----------


def test_extract_ascii_finds_basic_string():
    data = b"\x00\x01hello\x00world\x00\xff"
    assert _extract_ascii(data, min_length=4) == ["hello", "world"]


def test_extract_ascii_respects_min_length():
    data = b"foo\x00\x00hello\x00"
    # 'foo' = 3 chars → filtered out with min_length=4
    assert _extract_ascii(data, min_length=4) == ["hello"]


def test_extract_ascii_ignores_non_printable():
    data = b"good\x01\x02bad\x00text\x00"
    assert _extract_ascii(data, min_length=4) == ["good", "text"]


def test_extract_ascii_empty():
    assert _extract_ascii(b"\x00\x01\xff\xfe", min_length=4) == []


# ---------- _extract_utf16le ----------


def test_extract_utf16le_finds_wide_string():
    # 'API' in UTF-16LE = A\x00P\x00I\x00
    data = b"\xff" + "hello".encode("utf-16le") + b"\xff\xff"
    assert _extract_utf16le(data, min_length=4) == ["hello"]


def test_extract_utf16le_respects_min_length():
    data = "abc".encode("utf-16le") + b"\xff" + "hello".encode("utf-16le")
    assert _extract_utf16le(data, min_length=4) == ["hello"]


# ---------- get_shellcode_strings (public API) ----------


def test_get_shellcode_strings_returns_both_kinds():
    ascii_part = b"cmd.exe"
    # \xff\xff is a clean separator: no ASCII printable, no valid UTF-16LE pair
    wide_part = "kernel32".encode("utf-16le")
    data = ascii_part + b"\xff\xff" + wide_part
    result = get_shellcode_strings(data)
    assert "cmd.exe" in result["ascii"]
    assert "kernel32" in result["utf16le"]


def test_get_shellcode_strings_default_min_length():
    """Default is 4 → strings shorter than 4 chars are dropped."""
    data = b"ab\x00abcd\x00abcde\x00"
    result = get_shellcode_strings(data)
    assert "abcd" in result["ascii"]
    assert "abcde" in result["ascii"]
    assert "ab" not in result["ascii"]


def test_get_shellcode_strings_on_easy_shellcode_finds_urlmon():
    """Real-world sanity check: easy shellcode contains 'urlmon.dll'."""
    from src.tp2.utils.lib import load_shellcode
    data = load_shellcode("shellcodes/easy.txt")
    result = get_shellcode_strings(data)
    assert any("urlmon.dll" in s for s in result["ascii"])


def test_default_min_length_constant():
    assert DEFAULT_MIN_LENGTH == 4


# ---------- get_capstone_analysis ----------


def test_capstone_disassembles_simple_x86():
    """
    Sanity check on a well-known x86 sequence:
    - 0x90 = NOP
    - 0x31 0xC0 = XOR EAX, EAX
    - 0xC3 = RET
    """
    from src.tp2.utils.analyzer import get_capstone_analysis
    result = get_capstone_analysis(b"\x90\x31\xc0\xc3")
    assert len(result) == 3
    assert result[0]["mnemonic"] == "nop"
    assert result[1]["mnemonic"] == "xor"
    assert result[1]["op_str"] == "eax, eax"
    assert result[2]["mnemonic"] == "ret"


def test_capstone_returns_addresses_from_base():
    """Addresses start at base_address and increment per instruction size."""
    from src.tp2.utils.analyzer import get_capstone_analysis
    result = get_capstone_analysis(b"\x90\x90\x90", base_address=0x2000)
    assert result[0]["address"] == 0x2000
    assert result[1]["address"] == 0x2001
    assert result[2]["address"] == 0x2002


def test_capstone_empty_input():
    from src.tp2.utils.analyzer import get_capstone_analysis
    assert get_capstone_analysis(b"") == []


def test_capstone_stops_on_undecodable_byte():
    """Capstone stops (silently) when it hits an invalid opcode."""
    from src.tp2.utils.analyzer import get_capstone_analysis
    # \x90 (nop) then \xff\xff\xff\xff which is not a valid standalone insn
    # at least the first NOP should be there
    result = get_capstone_analysis(b"\x90\xff\xff\xff\xff")
    assert result[0]["mnemonic"] == "nop"


def test_capstone_on_easy_shellcode():
    """Real-world sanity: easy shellcode disassembles to > 20 instructions."""
    from src.tp2.utils.lib import load_shellcode
    from src.tp2.utils.analyzer import get_capstone_analysis
    data = load_shellcode("shellcodes/easy.txt")
    result = get_capstone_analysis(data)
    assert len(result) > 20
    # First instruction of the easy shellcode is a JMP (EB 54)
    assert result[0]["mnemonic"] == "jmp"


    # ---------- get_pylibemu_analysis (unicorn-backed) ----------

def test_pylibemu_returns_expected_shape():
    """Empty payload: no crash, structured result."""
    from src.tp2.utils.analyzer import get_pylibemu_analysis
    # A single ret at the very start returns immediately
    result = get_pylibemu_analysis(b"\xc3")
    assert "detected_apis" in result
    assert "instructions_executed" in result
    assert "error" in result
    assert isinstance(result["detected_apis"], list)

def test_pylibemu_counts_instructions():
    """Simple NOP sled: instructions_executed reflects the emulation."""
    from src.tp2.utils.analyzer import get_pylibemu_analysis
    result = get_pylibemu_analysis(b"\x90" * 10 + b"\xc3")
    assert result["instructions_executed"] >= 10

def test_pylibemu_detects_known_hash_in_ebx():
    """
    Handcrafted stub that loads the ROR13 hash of 'LoadLibraryA' into EBX,
    then rets. The hook should detect and record 'LoadLibraryA'.
    """
    from src.tp2.utils.analyzer import get_pylibemu_analysis
    from src.tp2.utils.api_hashes import ror13_hash
    hash_val = ror13_hash("LoadLibraryA")
    # mov ebx, imm32 → BB imm32(LE) ; then ret (C3)
    stub = b"\xbb" + hash_val.to_bytes(4, "little") + b"\xc3"
    result = get_pylibemu_analysis(stub)
    assert "LoadLibraryA" in result["detected_apis"]

def test_pylibemu_on_easy_shellcode_runs_without_python_crash():
    """
    Real-world sanity: the easy shellcode should emulate for at least a
    few instructions before crashing on an invalid memory access, and
    the function must return cleanly (no Python exception).
    """
    from src.tp2.utils.lib import load_shellcode
    from src.tp2.utils.analyzer import get_pylibemu_analysis
    data = load_shellcode("shellcodes/easy.txt")
    result = get_pylibemu_analysis(data)
    assert result["instructions_executed"] > 0
    # emulation almost certainly fails at some point → we accept it
        # but the function returns cleanly