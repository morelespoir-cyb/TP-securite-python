from src.tp3.utils.captcha import Captcha


def test_captcha_init():
    # Given
    url = "http://example.com/captcha"

    # When
    captcha = Captcha(url)

    # Then
    assert captcha.url == url
    assert captcha.image == ""
    assert captcha.value == ""


def test_solve():
    # Given
    captcha = Captcha("http://example.com/captcha")

    # When
    captcha.solve()

    # Then
    assert captcha.value == "FIXME"


def test_capture():
    # Given
    captcha = Captcha("http://example.com/captcha")

    # When
    captcha.capture()

    # Then
    # This is a minimal test since the method doesn't do anything yet
    assert captcha.image == ""


def test_get_value():
    # Given
    captcha = Captcha("http://example.com/captcha")
    captcha.value = "TEST123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "TEST123"
