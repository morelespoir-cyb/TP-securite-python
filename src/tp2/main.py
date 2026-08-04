"""TP2 entry point — analyse Windows shellcodes."""
import argparse
import sys

from tp2.utils.analyzer import (
    get_capstone_analysis,
    get_llm_analysis,
    get_pylibemu_analysis,
    get_shellcode_strings,
)
from tp2.utils.config import logger
from tp2.utils.lib import load_shellcode


MAX_INSTRUCTIONS_LOGGED = 30


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tp2",
        description="Analyse a Windows shellcode: strings + capstone + pylibemu + LLM",
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="path to the shellcode file (\\xHH escape format)",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="skip the LLM analysis step (useful if Ollama is not running)",
    )
    args = parser.parse_args()

    try:
        shellcode = load_shellcode(args.file)
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Cannot load shellcode: {e}")
        return 1

    logger.info(f"Testing shellcode of size {len(shellcode)}B")

    # --- Strings extraction ---
    strings = get_shellcode_strings(shellcode)
    for kind, items in strings.items():
        label = {
            "ascii": "ASCII (raw)",
            "utf16le": "UTF-16LE",
            "stack_pushed": "Stack-pushed (Metasploit-style)",
        }.get(kind, kind)
        if items:
            logger.info(f"Strings — {label} — {len(items)} found:")
            for s in items:
                logger.info(f"  '{s}'")
        else:
            logger.info(f"Strings — {label} — none")

    # --- Capstone disassembly ---
    instructions = get_capstone_analysis(shellcode)
    total = len(instructions)
    shown = min(total, MAX_INSTRUCTIONS_LOGGED)
    logger.info(f"Capstone — {total} instructions decoded (showing first {shown}):")
    for insn in instructions[:shown]:
        logger.info(
            f"  0x{insn['address']:04x}: "
            f"{insn['mnemonic']:<6} {insn['op_str']}"
        )
    if total > shown:
        logger.info(f"  ... {total - shown} more instructions truncated")

    # --- Pylibemu-style emulation ---
    emu = get_pylibemu_analysis(shellcode)
    logger.info(
        f"Emulation — {emu['instructions_executed']} instructions executed"
    )
    if emu["detected_apis"]:
        logger.info(
            f"Detected Windows APIs ({len(emu['detected_apis'])}):"
        )
        for api in emu["detected_apis"]:
            logger.info(f"  - {api}")
    else:
        logger.info("Detected Windows APIs: none")
    if emu["error"]:
        logger.info(f"Emulation note: {emu['error']}")

    # --- LLM synthesis ---
    if args.skip_llm:
        logger.info("LLM analysis skipped (--skip-llm)")
    else:
        logger.info("Querying LLM for synthesis...")
        llm_output = get_llm_analysis(shellcode, strings, instructions, emu)
        logger.info(f"Explication LLM :\n{llm_output}")

    logger.info("Shellcode analysed !")
    return 0


if __name__ == "__main__":
    sys.exit(main())