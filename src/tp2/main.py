"""TP2 entry point — analyse Windows shellcodes."""
import argparse
import sys

from tp2.utils.config import logger
from tp2.utils.lib import load_shellcode


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

    # Lots 2-5 will plug analysers here:
    #   strings = get_shellcode_strings(shellcode)
    #   capstone_out = get_capstone_analysis(shellcode)
    #   pylibemu_out = get_pylibemu_analysis(shellcode)
    #   llm_out = get_llm_analysis(shellcode, strings, capstone_out, pylibemu_out)

    logger.info("Shellcode analysed !")
    return 0


if __name__ == "__main__":
    sys.exit(main())