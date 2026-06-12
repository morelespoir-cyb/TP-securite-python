import pytest
from unittest.mock import patch

from src.tp1.utils.capture import Capture


@pytest.fixture
def capture():
    """
    Capture instance with choose_interface mocked so the constructor
    doesn't block on stdin during tests.
    """
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        yield Capture()


def test_capture_init(capture):
    assert capture.interface == ""
    assert capture.summary == ""
    assert capture.packets == []


def test_capture_traffic_no_interface(capture):
    """When no interface is selected, capture is skipped, packets stay empty."""
    capture.interface = ""
    capture.capture_traffic()
    assert capture.packets == []


@patch("src.tp1.utils.capture.sniff")
def test_capture_traffic_calls_sniff(mock_sniff, capture):
    """When interface is set, sniff is called with correct args, packets stored."""
    capture.interface = "eth0"
    fake_packets = ["pkt1", "pkt2", "pkt3"]
    mock_sniff.return_value = fake_packets

    capture.capture_traffic(count=10, timeout=5)

    mock_sniff.assert_called_once_with(iface="eth0", count=10, timeout=5)
    assert capture.packets == fake_packets


@patch("src.tp1.utils.capture.sniff", side_effect=PermissionError("no root"))
def test_capture_traffic_handles_permission_error(_mock_sniff, capture):
    """Permission errors are caught, packets reset to empty."""
    capture.interface = "eth0"
    capture.capture_traffic()
    assert capture.packets == []


def test_sort_network_protocols(capture):
    assert capture.sort_network_protocols() == ""


def test_get_all_protocols(capture):
    assert capture.get_all_protocols() == ""


def test_analyse(capture):
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary(capture):
    capture.summary = "Test summary"
    assert capture.get_summary() == "Test summary"


def test_gen_summary(capture):
    assert capture._gen_summary() == ""