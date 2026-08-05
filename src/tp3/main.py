"""TP3 entry point — solve challenge CAPTCHAs and collect flags."""
import argparse
import sys

from tp3.utils.config import logger
from tp3.utils.session import Session


DEFAULT_SERVER = "31.220.95.27:9002"
DEFAULT_CHALLENGES = ["1", "2"]  # extensible up to 5 if the prof brings more
MAX_ATTEMPTS_PER_CHALLENGE = 30


def solve_challenge(url: str, max_attempts: int = MAX_ATTEMPTS_PER_CHALLENGE) -> str | None:
    """
    Solve a single challenge, retrying up to `max_attempts` times.

    OCR is noisy — Tesseract will sometimes misread a character on
    real-world captchas. The safety cap prevents infinite loops when
    the challenge is unsolvable (server down, unsupported font, etc.).

    :param url: challenge URL
    :param max_attempts: safety cap on retries
    :return: the captured flag or None if all attempts failed
    """
    session = Session(url)
    for attempt in range(1, max_attempts + 1):
        try:
            session.prepare_request()
            session.submit_request()
        except Exception as e:
            logger.warning(f"Attempt {attempt}/{max_attempts} on {url} failed: {e}")
            continue

        if session.process_response():
            logger.info(f"Smell good ! Solved {url} on attempt {attempt}")
            return session.get_flag()

        logger.debug(f"Attempt {attempt}/{max_attempts} on {url} incorrect, retrying")

    logger.error(f"Gave up on {url} after {max_attempts} attempts")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tp3",
        description="Solve challenge CAPTCHAs and collect flags",
    )
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER,
        help=f"challenge server ip:port (default {DEFAULT_SERVER})",
    )
    parser.add_argument(
        "--challenges",
        nargs="+",
        default=DEFAULT_CHALLENGES,
        help="challenge IDs to attempt (default: 1 2)",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=MAX_ATTEMPTS_PER_CHALLENGE,
        help=f"retries per challenge (default {MAX_ATTEMPTS_PER_CHALLENGE})",
    )
    args = parser.parse_args()

    logger.info("Starting TP3")

    flags: dict[str, str | None] = {}
    for challenge_id in args.challenges:
        url = f"http://{args.server}/captcha{challenge_id}/"
        logger.info(f"Challenge {challenge_id} → {url}")
        flag = solve_challenge(url, max_attempts=args.max_attempts)
        flags[url] = flag
        if flag:
            logger.info(f"Flag for {url} : {flag}")

    logger.info("=" * 50)
    logger.info("Summary:")
    solved = sum(1 for f in flags.values() if f)
    total = len(flags)
    for url, flag in flags.items():
        status = flag if flag else "FAILED"
        logger.info(f"  {url} → {status}")
    logger.info(f"Solved: {solved}/{total}")

    return 0 if solved == total else 1


if __name__ == "__main__":
    sys.exit(main())
