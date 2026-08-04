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


def test_get_shellcode_strings_returns_all_kinds():
    ascii_part = b"cmd.exe"
    wide_part = "kernel32".encode("utf-16le")
    data = ascii_part + b"\xff\xff" + wide_part
    result = get_shellcode_strings(data)
    assert set(result.keys()) == {"ascii", "utf16le", "stack_pushed"}
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

    # ---------- get_llm_analysis ----------

def test_build_llm_prompt_includes_all_sections():
    from src.tp2.utils.analyzer import _build_llm_prompt
    prompt = _build_llm_prompt(
        strings={"ascii": ["urlmon.dll", "C:\\U.exe"], "utf16le": []},
        instructions=[
            {"address": 0x1000, "mnemonic": "jmp", "op_str": "0x1056", "bytes": "eb54"},
            {"address": 0x1002, "mnemonic": "mov", "op_str": "esi, eax", "bytes": "89c6"},
        ],
        emulation={"detected_apis": ["LoadLibraryA"], "instructions_executed": 100, "error": None},
    )
    assert "urlmon.dll" in prompt
    assert "U.exe" in prompt
    assert "0x1000" in prompt
    assert "jmp" in prompt
    assert "LoadLibraryA" in prompt

def test_build_llm_prompt_handles_empty_inputs():
    from src.tp2.utils.analyzer import _build_llm_prompt
    prompt = _build_llm_prompt(
        strings={"ascii": [], "utf16le": []},
        instructions=[],
        emulation={"detected_apis": [], "instructions_executed": 0, "error": None},
    )
    assert "aucune" in prompt

def test_build_llm_prompt_truncates_long_instructions():
    from src.tp2.utils.analyzer import _build_llm_prompt
    long_insns = [
        {"address": i, "mnemonic": "nop", "op_str": "", "bytes": "90"}
        for i in range(100)
    ]
    prompt = _build_llm_prompt(
        strings={"ascii": [], "utf16le": []},
        instructions=long_insns,
        emulation={"detected_apis": [], "instructions_executed": 100, "error": None},
        max_instructions=10,
    )
    # We showed 10, so 90 should be "more truncated"
    assert "90 more truncated" in prompt

def test_llm_analysis_handles_connection_error(monkeypatch):
    """Ollama down → explanatory message, no exception."""
    import requests
    from src.tp2.utils.analyzer import get_llm_analysis

    def _raise_conn_error(*_args, **_kwargs):
        raise requests.exceptions.ConnectionError("simulated")

    monkeypatch.setattr(
        "src.tp2.utils.analyzer.requests.post", _raise_conn_error
    )
    result = get_llm_analysis(
        b"\x90",
        strings={"ascii": [], "utf16le": []},
        instructions=[],
        emulation={"detected_apis": [], "instructions_executed": 0, "error": None},
    )
    assert "unreachable" in result.lower()

def test_llm_analysis_handles_timeout(monkeypatch):
    """Ollama hangs → explicit timeout message."""
    import requests
    from src.tp2.utils.analyzer import get_llm_analysis

    def _raise_timeout(*_args, **_kwargs):
        raise requests.exceptions.Timeout("simulated")

    monkeypatch.setattr(
        "src.tp2.utils.analyzer.requests.post", _raise_timeout
    )
    result = get_llm_analysis(
        b"\x90",
        strings={"ascii": [], "utf16le": []},
        instructions=[],
        emulation={"detected_apis": [], "instructions_executed": 0, "error": None},
    )
    assert "timeout" in result.lower()

def test_llm_analysis_returns_llm_text_on_success(monkeypatch):
    """Ollama returns 200 with JSON → we return the 'response' field."""
    from src.tp2.utils.analyzer import get_llm_analysis

    class _FakeResp:
        status_code = 200
        text = ""

        def json(self):
            return {"response": "Ce shellcode est un downloader.  "}

    monkeypatch.setattr(
        "src.tp2.utils.analyzer.requests.post",
        lambda *a, **kw: _FakeResp(),
    )
    result = get_llm_analysis(
        b"\x90",
        strings={"ascii": ["urlmon.dll"], "utf16le": []},
        instructions=[],
        emulation={"detected_apis": [], "instructions_executed": 0, "error": None},
    )
    # trailing spaces stripped
    assert result == "Ce shellcode est un downloader."

def test_llm_analysis_handles_http_error(monkeypatch):
    """Ollama returns non-200 → informative error message."""
    from src.tp2.utils.analyzer import get_llm_analysis

    class _FakeResp:
        status_code = 404
        text = "model 'zzz' not found"

        def json(self):
            return {}

    monkeypatch.setattr(
        "src.tp2.utils.analyzer.requests.post",
        lambda *a, **kw: _FakeResp(),
    )
    result = get_llm_analysis(
        b"\x90",
        strings={"ascii": [], "utf16le": []},
        instructions=[],
        emulation={"detected_apis": [], "instructions_executed": 0, "error": None},
    )
    assert "404" in result
    assert "not found" in result


    # ---------- extract_stack_pushed_strings ----------

def test_stack_pushed_simple_run():
        """
        Two consecutive `push imm32`:
        - push 0x64636261 → bytes 61 62 63 64 → "abcd"
        - push 0x68676665 → bytes 65 66 67 68 → "efgh"
        Last push first (stack grows down) → "efghabcd"
        """
        from src.tp2.utils.analyzer import extract_stack_pushed_strings
        sc = b"\x68\x61\x62\x63\x64\x68\x65\x66\x67\x68"
        result = extract_stack_pushed_strings(sc, min_length=4)
        assert result == ["efghabcd"]

def test_stack_pushed_ignores_short_runs():
        """Single push (4 bytes only) is skipped when min_length=5."""
        from src.tp2.utils.analyzer import extract_stack_pushed_strings
        sc = b"\x68\x61\x62\x63\x64"
        assert extract_stack_pushed_strings(sc, min_length=5) == []

def test_stack_pushed_skips_non_printable_runs():
        """Runs whose decoded bytes are mostly non-printable get filtered out."""
        from src.tp2.utils.analyzer import extract_stack_pushed_strings
        # Two pushes but the bytes are 0x01, 0x02 etc. → not printable
        sc = b"\x68\x01\x02\x03\x04\x68\x05\x06\x07\x08"
        assert extract_stack_pushed_strings(sc) == []

def test_stack_pushed_stops_on_non_push():
        """A run terminates on any non-`push imm32` opcode."""
        from src.tp2.utils.analyzer import extract_stack_pushed_strings
        # push "abcd", then RET (0xc3), then push "efgh"
        sc = b"\x68\x61\x62\x63\x64\xc3\x68\x65\x66\x67\x68"
        result = extract_stack_pushed_strings(sc, min_length=4)
        # Each isolated single push produces 4 chars → both should be captured
        assert "abcd" in result
        assert "efgh" in result

def test_stack_pushed_on_medium_shellcode_finds_cmd():
        """
        Real-world sanity: medium shellcode is a 'net user /ADD' payload
        that push-assembles its command line on the stack.
        """
        from src.tp2.utils.lib import load_shellcode
        from src.tp2.utils.analyzer import extract_stack_pushed_strings
        data = load_shellcode("shellcodes/medium.txt")
        result = extract_stack_pushed_strings(data)
        joined = " ".join(result).lower()
        assert "cmd" in joined
        assert "net" in joined
        assert "add" in joined

def test_stack_pushed_on_hard_shellcode_finds_winsock_hint():
        """Hard shellcode is a reverse TCP shell → ws2_32 must appear."""
        from src.tp2.utils.lib import load_shellcode
        from src.tp2.utils.analyzer import extract_stack_pushed_strings
        data = load_shellcode("shellcodes/hard.txt")
        result = extract_stack_pushed_strings(data)
        joined = " ".join(result).lower()
        assert "ws2_32" in joined