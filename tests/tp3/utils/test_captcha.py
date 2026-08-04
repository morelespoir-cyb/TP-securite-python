from unittest.mock import MagicMock, patch

import pytest

from src.tp3.utils.captcha import Captcha
from tests.tp3.utils.captcha_fixtures import (
    image_to_png_bytes,
    make_captcha_image,
)


def test_captcha_init():
    captcha = Captcha("http://example.com/captcha1/")
    assert captcha.url == "http://example.com/captcha1/"
    assert captcha.image == ""
    assert captcha.value == ""
    assert captcha.token == ""


def _mock_get_side_effect(html_body, image_bytes):
    def _side_effect(url, *args, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if url.endswith(".png") or "/image" in url:
            resp.content = image_bytes
        else:
            resp.text = html_body
        return resp
    return _side_effect


def test_capture_downloads_image_from_absolute_url():
    img = make_captcha_image("ABC12")
    png = image_to_png_bytes(img)
    html = '<html><img src="http://example.com/captcha1/img.png"></html>'
    captcha = Captcha("http://example.com/captcha1/")
    with patch.object(
        captcha._session, "get",
        side_effect=_mock_get_side_effect(html, png),
    ):
        captcha.capture()
    assert captcha.image is not None
    assert captcha.image.size == (200, 60)


def test_capture_resolves_relative_image_url():
    img = make_captcha_image("XYZ")
    png = image_to_png_bytes(img)
    html = '<html><img src="img.png"></html>'
    captcha = Captcha("http://example.com/captcha1/")
    with patch.object(
        captcha._session, "get",
        side_effect=_mock_get_side_effect(html, png),
    ):
        captcha.capture()
    assert captcha.image is not None


def test_capture_extracts_token_from_hidden_input():
    img = make_captcha_image("ABC")
    png = image_to_png_bytes(img)
    html = (
        '<html>'
        '<input type="hidden" name="token" value="abc123xyz">'
        '<img src="img.png">'
        '</html>'
    )
    captcha = Captcha("http://example.com/captcha1/")
    with patch.object(
        captcha._session, "get",
        side_effect=_mock_get_side_effect(html, png),
    ):
        captcha.capture()
    assert captcha.token == "abc123xyz"


def test_capture_no_image_raises():
    captcha = Captcha("http://example.com/captcha1/")
    with patch.object(
        captcha._session, "get",
        side_effect=_mock_get_side_effect("<html>no image</html>", b""),
    ):
        with pytest.raises(ValueError, match="No <img>"):
            captcha.capture()



def test_get_value_returns_stored_value():
    captcha = Captcha("http://example.com/captcha1/")
    captcha.value = "TEST123"
    assert captcha.get_value() == "TEST123"


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
    matches = sum(1 for a, b in zip(captcha.value, "R2D2X") if a == b)
    assert matches >= 4, f"OCR too weak: got {captcha.value!r}"


def test_solve_filters_out_non_whitelisted_chars():
    """Whitelist keeps only allowed chars even if tesseract hallucinates."""
    captcha = Captcha("http://example.com/captcha1/")
    captcha.image = make_captcha_image("ABC", noise_level=0)
    captcha.solve(whitelist="ABC")
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
