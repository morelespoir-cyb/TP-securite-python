from unittest.mock import patch

from src.tp1.utils.lib import hello_world, choose_interface


def test_when_hello_world_then_return_hello_world():
    assert hello_world() == "hello world"


@patch("src.tp1.utils.lib.get_if_list", return_value=[])
def test_choose_interface_no_interface(_mock_get_if_list):
    """When no interface is available, returns empty string."""
    assert choose_interface() == ""


@patch("builtins.input", return_value="1")
@patch("src.tp1.utils.lib.get_if_list", return_value=["eth0", "wlan0"])
def test_choose_interface_valid_choice(_mock_get_if_list, _mock_input):
    """User picks option 1 → returns first interface."""
    assert choose_interface() == "eth0"


@patch("builtins.input", side_effect=["abc", "99", "2"])
@patch("src.tp1.utils.lib.get_if_list", return_value=["eth0", "wlan0"])
def test_choose_interface_invalid_then_valid(_mock_get_if_list, _mock_input):
    """User types garbage, out-of-range, then valid → returns wlan0."""
    assert choose_interface() == "wlan0"