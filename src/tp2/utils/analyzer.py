"""Shellcode analyzers: strings, capstone, pylibemu, LLM."""
import re
import json
import os

import requests
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EBX, UC_X86_REG_EIP

from src.tp2.utils.api_hashes import API_HASHES

# Minimum length for a candidate string to be considered "interesting"
DEFAULT_MIN_LENGTH = 4

# push imm32 opcode: 0x68 followed by 4 bytes of immediate
_PUSH_IMM32_OPCODE = 0x68
_PUSH_IMM32_LEN = 5   # opcode + 4 bytes


def extract_stack_pushed_strings(
    shellcode: bytes,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list[str]:
    """
    Reconstruct strings that a Metasploit-style shellcode assembles on
    the stack via consecutive `push imm32` instructions.

    Why this matters: Metasploit shellcodes commonly build their string
    arguments (paths, DLL names, command lines) byte-by-byte on the
    stack rather than embedding them as data. A single ASCII scan of
    the raw shellcode bytes shows a fragmented mess like
    'hexe hcmd. h/c nh net' — the `h` are the 0x68 push opcodes, and
    the runtime string reads back from stack in reverse push order.

    Algorithm:
    - Walk the shellcode looking for runs of `0x68 XX XX XX XX` blocks
    - For each run, take the 4 immediate bytes of each push
    - Concatenate them in REVERSE order (last push first) — that's the
      order in which the CPU will read the string once ESP points to it
    - Keep runs whose printable-ASCII decoding is >= min_length chars

    :param shellcode: raw shellcode bytes
    :param min_length: minimum chars for a reconstructed string to count
    :return: list of reconstructed strings, in order of appearance
    """
    reconstructed: list[str] = []
    i = 0
    while i < len(shellcode):
        # Detect a run of consecutive `push imm32`
        run_imms: list[bytes] = []
        while (
            i + _PUSH_IMM32_LEN <= len(shellcode)
            and shellcode[i] == _PUSH_IMM32_OPCODE
        ):
            run_imms.append(shellcode[i + 1 : i + _PUSH_IMM32_LEN])
            i += _PUSH_IMM32_LEN

        if run_imms:
            # Stack grows down: last push ends up at lowest address (front
            # of the resulting string). So reading the string means reading
            # pushes in reverse order.
            joined = b"".join(reversed(run_imms))
            decoded = joined.decode("ascii", errors="replace").rstrip("\x00")
            # Keep only if it's mostly printable and long enough
            printable_ratio = sum(
                1 for c in decoded if 0x20 <= ord(c) <= 0x7E
            ) / max(len(decoded), 1)
            if len(decoded) >= min_length and printable_ratio >= 0.85:
                reconstructed.append(decoded)
        else:
            i += 1

    return reconstructed


def get_shellcode_strings(
    shellcode: bytes,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> dict[str, list[str]]:
    """
    Extract printable strings from a shellcode using three methods:
    - Raw ASCII scan
    - Raw UTF-16LE scan
    - Stack-pushed string reconstruction (Metasploit-style)

    The 'stack_pushed' category is the most useful for real-world
    Metasploit shellcodes where strings are assembled on the stack.

    :param shellcode: raw shellcode bytes
    :param min_length: minimum length for a string to be reported
    :return: dict with keys 'ascii', 'utf16le', 'stack_pushed'
    """
    return {
        "ascii": _extract_ascii(shellcode, min_length),
        "utf16le": _extract_utf16le(shellcode, min_length),
        "stack_pushed": extract_stack_pushed_strings(shellcode, min_length),
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


def get_capstone_analysis(
    shellcode: bytes,
    base_address: int = 0x1000,
) -> list[dict]:
    """
    Disassemble a shellcode as x86 32-bit and return one dict per instruction.

    Uses Capstone, the same disassembler engine as IDA Pro plugins, radare2,
    Ghidra, and many CTF/malware tools. We stick to x86 32-bit because all
    three course shellcodes are 32-bit (typical Metasploit windows/... range).

    :param shellcode: raw shellcode bytes
    :param base_address: virtual address the disassembler pretends the code
        was loaded at. Affects branch target display only, not decoding.
        0x1000 is a conventional 'looks like real code' base.
    :return: list of {'address', 'mnemonic', 'op_str', 'bytes'} per insn
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False  # we don't need operand introspection here
    instructions: list[dict] = []
    for insn in md.disasm(shellcode, base_address):
        instructions.append(
            {
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            }
        )
    return instructions


# Memory layout for shellcode emulation
_EMU_BASE = 0x1000
_EMU_MEM_SIZE = 0x400_000  # 4 MB, plenty for shellcode + fake stack
_EMU_STACK_BASE = 0x300_000
_EMU_MAX_INSTRUCTIONS = 5000  # safety cap: shellcodes usually decode < 500


def get_pylibemu_analysis(shellcode: bytes) -> dict:
    """
    Emulate the shellcode with Unicorn engine and return the list of
    Windows APIs it attempted to resolve.

    NOTE: the function is named `get_pylibemu_analysis` to match the TP2
    interface contract, but internally we use Unicorn (QEMU-based, maintained
    2025) instead of pylibemu (libemu, unmaintained since 2011). The
    end result is equivalent: we surface which Windows APIs the shellcode
    would call, without executing it on a real Windows box.

    Detection strategy — the 3 course shellcodes use the Metasploit ROR13
    API resolution scheme: they hash each PE export name at runtime and
    compare it to a hardcoded target hash. We hook every instruction, and
    whenever EBX matches a known ROR13 hash (see api_hashes.py), we record
    the resolved API name.

    Emulation is best-effort: the shellcodes expect a real PEB structure
    that we don't provide, so they crash eventually. We collect the APIs
    detected before the crash — that's usually enough to know the intent.

    :param shellcode: raw shellcode bytes
    :return: dict with:
        - 'detected_apis': list of API names (deduplicated, order of appearance)
        - 'instructions_executed': how many insns were emulated before stop
        - 'error': error message if emulation crashed, else None
    """
    detected: list[str] = []
    detected_set: set[str] = set()
    counters = {"n": 0}

    def _hook_code(uc, address, size, user_data):
        counters["n"] += 1
        if counters["n"] > _EMU_MAX_INSTRUCTIONS:
            uc.emu_stop()
            return
        ebx = uc.reg_read(UC_X86_REG_EBX)
        name = API_HASHES.get(ebx)
        if name and name not in detected_set:
            detected_set.add(name)
            detected.append(name)

    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0, _EMU_MEM_SIZE)
    uc.mem_write(_EMU_BASE, shellcode)
    # Fake stack
    uc.reg_write(UC_X86_REG_EIP, _EMU_BASE)
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EBP
    uc.reg_write(UC_X86_REG_ESP, _EMU_STACK_BASE)
    uc.reg_write(UC_X86_REG_EBP, _EMU_STACK_BASE)
    uc.hook_add(UC_HOOK_CODE, _hook_code)

    error_msg = None
    try:
        uc.emu_start(_EMU_BASE, _EMU_BASE + len(shellcode))
    except UcError as e:
        error_msg = f"emulation stopped: {e}"

    return {
        "detected_apis": detected,
        "instructions_executed": counters["n"],
        "error": error_msg,
    }

# ---------- LLM analysis (Ollama backend) ----------

_LLM_DEFAULT_MODEL = "qwen2.5:1.5b"
_LLM_DEFAULT_URL = "http://localhost:11434/api/generate"
_LLM_TIMEOUT = 180  # seconds — qwen2.5:7b can take ~40s on CPU


_LLM_SYSTEM_PROMPT = (
    "Tu es un analyste malware. On te donne les résultats de trois "
    "analyseurs statiques/dynamiques d'un shellcode Windows x86 : "
    "les chaînes lisibles extraites, le désassemblage x86, et les "
    "API Windows résolues par émulation. Ton rôle est de répondre "
    "en français, en 3 à 5 phrases maximum, sans intro ni conclusion. "
    "Indique : (1) le type de shellcode (downloader, reverse shell, "
    "création de compte, etc.), (2) les indicateurs qui t'ont permis "
    "de conclure, (3) le risque associé. Reste factuel, pas de blabla."
)


def _build_llm_prompt(
    strings: dict[str, list[str]],
    instructions: list[dict],
    emulation: dict,
    max_instructions: int = 40,
) -> str:
    """
    Compose the analyst prompt from the three analyzer outputs.
    Instructions are truncated to keep the prompt under context window.
    """
    ascii_strings = strings.get("ascii", [])
    utf16_strings = strings.get("utf16le", [])
    stack_strings = strings.get("stack_pushed", [])

    insn_lines = [
        f"  0x{i['address']:04x}: {i['mnemonic']:<6} {i['op_str']}"
        for i in instructions[:max_instructions]
    ]
    if len(instructions) > max_instructions:
        insn_lines.append(
            f"  ... ({len(instructions) - max_instructions} more truncated)"
        )

    parts = [
        "== Chaînes reconstruites depuis la pile (push imm32) ==",
        "Ces chaînes ont été assemblées instruction par instruction sur "
        "la pile — c'est la technique Metasploit classique. Elles sont "
        "les indicateurs les plus fiables du comportement du shellcode.",
        "\n".join(f"  - {s!r}" for s in stack_strings) or "  (aucune)",
        "",
        "== Chaînes ASCII brutes trouvées ==",
        "\n".join(f"  - {s!r}" for s in ascii_strings) or "  (aucune)",
        "",
        "== Chaînes UTF-16LE trouvées ==",
        "\n".join(f"  - {s!r}" for s in utf16_strings) or "  (aucune)",
        "",
        f"== Désassemblage x86 (premières {max_instructions} instructions) ==",
        "\n".join(insn_lines) or "  (rien à désassembler)",
        "",
        "== APIs Windows détectées par émulation ==",
        "\n".join(f"  - {api}" for api in emulation.get("detected_apis", []))
        or "  (aucune — l'émulation n'a pas pu résoudre les APIs)",
        "",
        "Analyse ce shellcode. Concentre-toi surtout sur les chaînes "
        "reconstruites depuis la pile.",
    ]
    return "\n".join(parts)


def get_llm_analysis(
    shellcode: bytes,
    strings: dict[str, list[str]],
    instructions: list[dict],
    emulation: dict,
) -> str:
    """
    Ask a local LLM (Ollama backend) to synthesise the three analyzer
    outputs into a natural-language verdict about the shellcode intent.

    Configuration via env vars:
    - TP2_LLM_MODEL: model name (default 'qwen2.5:1.5b')
    - TP2_LLM_URL:   Ollama API endpoint (default 'http://localhost:11434/api/generate')

    Failure modes are handled gracefully:
    - Ollama unreachable → returns an explanatory message, no exception
    - Model missing     → returns Ollama's error message
    - Timeout           → explicit timeout message

    The `shellcode` bytes are accepted for future use (e.g. sending the
    raw hex to the model) but are not sent in the current prompt to keep
    the context window manageable.

    :return: LLM's analysis as a French string (or an error message)
    """
    model = os.environ.get("TP2_LLM_MODEL", _LLM_DEFAULT_MODEL)
    url = os.environ.get("TP2_LLM_URL", _LLM_DEFAULT_URL)

    prompt = _build_llm_prompt(strings, instructions, emulation)
    payload = {
        "model": model,
        "system": _LLM_SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},  # low temp = more factual output
    }

    try:
        response = requests.post(url, json=payload, timeout=_LLM_TIMEOUT)
    except requests.exceptions.ConnectionError:
        return (
            f"[LLM unreachable] Cannot connect to Ollama at {url}. "
            "Is the service running? Try: 'sudo systemctl start ollama' "
            "or 'ollama serve &'."
        )
    except requests.exceptions.Timeout:
        return f"[LLM timeout] Model '{model}' took >{_LLM_TIMEOUT}s to answer."

    if response.status_code != 200:
        return (
            f"[LLM error {response.status_code}] "
            f"{response.text[:200]}"
        )

    try:
        data = response.json()
    except json.JSONDecodeError:
        return "[LLM error] Response is not valid JSON."

    return data.get("response", "").strip() or "[LLM empty response]"