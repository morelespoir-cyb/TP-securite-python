"""Captcha client — fetches, decodes and solves a challenge captcha."""
import io

import requests
import pytesseract
from bs4 import BeautifulSoup
from PIL import Image


_HTTP_TIMEOUT = 15  # seconds


class Captcha:
    """
    A single captcha challenge.

    Lifecycle:
        1. capture()   — fetch the challenge page, parse it, download image
        2. solve()     — OCR the image, populate self.value
        3. get_value() — return the OCR result
    """

    def __init__(self, url: str):
        self.url = url
        self.image: Image.Image | str = ""
        self.value: str = ""
        self.token: str = ""
        self._session = requests.Session()

    def capture(self) -> None:
        """
        Fetch the challenge HTML page, parse it, download the captcha image.

        Populates:
            self.image: PIL.Image object of the downloaded captcha
            self.token: session/CSRF token if present in the page
        """
        resp = self._session.get(self.url, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        for name in ("token", "csrf", "csrf_token", "session_id"):
            hidden = soup.find("input", {"name": name})
            if hidden and hidden.get("value"):
                self.token = hidden["value"]
                break

        img_tag = soup.find("img")
        if img_tag is None or not img_tag.get("src"):
            raise ValueError(f"No <img> found on {self.url}")

        img_src = img_tag["src"]
        if not img_src.startswith(("http://", "https://")):
            base = self.url.rstrip("/")
            img_src = f"{base}/{img_src.lstrip('/')}"

        img_resp = self._session.get(img_src, timeout=_HTTP_TIMEOUT)
        img_resp.raise_for_status()

        self.image = Image.open(io.BytesIO(img_resp.content))

    def solve(self, whitelist: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") -> None:
        """
        OCR the captured image with pytesseract and populate self.value.

        Pipeline:
          1. Convert to grayscale (reduces color noise, keeps luminance)
          2. Binary threshold at 128 → sharpens char edges for OCR
          3. Feed to tesseract with a character whitelist to filter noise
          4. Strip whitespace, keep only whitelisted chars

        The whitelist defaults to uppercase alphanumeric — the vast majority
        of CAPTCHAs use this charset. Override for other charsets.

        :param whitelist: allowed characters in the OCR output
        :raises RuntimeError: if capture() has not been called yet
        """
        if not isinstance(self.image, Image.Image):
            raise RuntimeError("capture() must be called before solve()")

        # Preprocessing: grayscale then binary threshold
        grayscale = self.image.convert("L")
        binary = grayscale.point(lambda p: 0 if p < 128 else 255, mode="1")

        # Tesseract config:
        # - psm 8: treat image as single word (best for short captchas)
        # - tessedit_char_whitelist: restricts output charset
        config = (
            f"--psm 8 -c tessedit_char_whitelist={whitelist}"
        )
        raw = pytesseract.image_to_string(binary, config=config)

        # Keep only whitelisted characters and uppercase them
        allowed = set(whitelist)
        cleaned = "".join(c for c in raw.strip().upper() if c in allowed)
        self.value = cleaned

    def get_value(self) -> str:
        return self.value

    @property
    def session(self) -> requests.Session:
        """Expose the underlying HTTP session for downstream Session class."""
        return self._session

    # ---------- solve (Lot 2) ----------

    def test_solve_reads_clean_captcha():
        """Clean synthetic captcha → tesseract should read it perfectly."""
        captcha = Captcha("http://example.com/captcha1/")
        captcha.image = make_captcha_image("ABCDE", noise_level=0)
        captcha.solve()
        assert captcha.value == "ABCDE"

    def test_solve_reads_numeric_captcha():
        """Digits work too."""
        captcha = Captcha("http://example.com/captcha1/")
        captcha.image = make_captcha_image("12345", noise_level=0)
        captcha.solve()
        assert captcha.value == "12345"

    def test_solve_alphanumeric_captcha():
        """Mixed letters + digits with light noise."""
        captcha = Captcha("http://example.com/captcha1/")
        captcha.image = make_captcha_image("R2D2X", noise_level=1)
        captcha.solve()
        # Allow some OCR tolerance on noisy input: at least 4/5 chars right
        matches = sum(1 for a, b in zip(captcha.value, "R2D2X") if a == b)
        assert matches >= 4, f"OCR too weak: got {captcha.value!r}"

    def test_solve_filters_out_non_whitelisted_chars():
        """
        Even if tesseract hallucinates a punctuation mark, the whitelist
        keeps only allowed chars.
        """
        captcha = Captcha("http://example.com/captcha1/")
        captcha.image = make_captcha_image("ABC", noise_level=0)
        captcha.solve(whitelist="ABC")
        # If tesseract sees ABC → value is ABC. If it also detected garbage,
        # the whitelist filters it out.
        assert captcha.value == "ABC"

    def test_solve_without_capture_raises():
        """Calling solve() before capture() raises a clear error."""
        captcha = Captcha("http://example.com/captcha1/")
        with pytest.raises(RuntimeError, match="capture"):
            captcha.solve()

    def test_solve_replaces_placeholder():
        """The old FIXME behavior is gone — solve now writes a real value."""
        captcha = Captcha("http://example.com/captcha1/")
        captcha.image = make_captcha_image("HELLO", noise_level=0)
        captcha.solve()
        assert captcha.value != "FIXME"
