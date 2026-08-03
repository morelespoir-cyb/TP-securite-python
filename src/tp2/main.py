"""TP2 entry point — analyse Windows shellcodes."""
import argparse
import sys

from tp2.utils.analyzer import (
    get_capstone_analysis,
    get_shellcode_strings,
)
from tp2.utils.config import logger
from tp2.utils.lib import load_shellcode


# Cap how many disassembled instructions we log (readability)
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
        if items:
            logger.info(f"Strings ({kind}) — {len(items)} found:")
            for s in items:
                logger.info(f"  '{s}'")
        else:
            logger.info(f"Strings ({kind}) — none")

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

    # Lots 4-5 will plug pylibemu + LLM here.

    logger.info("Shellcode analysed !")
    return 0


if __name__ == "__main__":
    sys.exit(main())