"""Shellcode analyzers: strings, capstone, pylibemu, LLM."""
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EBX, UC_X86_REG_EIP

from src.tp2.utils.api_hashes import API_HASHES

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