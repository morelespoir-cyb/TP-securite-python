import pytest
from unittest.mock import patch, MagicMock

from src.tp1.utils.capture import Capture


@pytest.fixture
def capture():
    """
    Capture instance with choose_interface mocked so the constructor
    doesn't block on stdin during tests.
    """
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        yield Capture()


def _make_packet(*layer_names: str) -> MagicMock:
    """
    Helper: build a fake Scapy packet whose .layers() returns the given
    sequence of layer classes (one class per name).
    """
    layer_classes = [type(name, (), {}) for name in layer_names]
    pkt = MagicMock()
    pkt.layers.return_value = layer_classes
    return pkt


def test_capture_init(capture):
    assert capture.interface == ""
    assert capture.summary == ""
    assert capture.packets == []


def test_capture_traffic_no_interface(capture):
    capture.interface = ""
    capture.capture_traffic()
    assert capture.packets == []


@patch("src.tp1.utils.capture.sniff")
def test_capture_traffic_calls_sniff(mock_sniff, capture):
    capture.interface = "eth0"
    fake_packets = ["pkt1", "pkt2", "pkt3"]
    mock_sniff.return_value = fake_packets
    capture.capture_traffic(count=10, timeout=5)
    mock_sniff.assert_called_once_with(iface="eth0", count=10, timeout=5)
    assert capture.packets == fake_packets


@patch("src.tp1.utils.capture.sniff", side_effect=PermissionError("no root"))
def test_capture_traffic_handles_permission_error(_mock_sniff, capture):
    capture.interface = "eth0"
    capture.capture_traffic()
    assert capture.packets == []


def test_get_all_protocols_empty(capture):
    """No packets → empty dict."""
    capture.packets = []
    assert capture.get_all_protocols() == {}


def test_get_all_protocols_counts_layers(capture):
    """Counts every layer occurrence across all packets."""
    capture.packets = [
        _make_packet("Ether", "IP", "TCP"),
        _make_packet("Ether", "IP", "TCP"),
        _make_packet("Ether", "IP", "UDP"),
    ]
    assert capture.get_all_protocols() == {
        "Ether": 3,
        "IP": 3,
        "TCP": 2,
        "UDP": 1,
    }


def test_sort_network_protocols_empty(capture):
    """No packets → empty list."""
    capture.packets = []
    assert capture.sort_network_protocols() == []


def test_sort_network_protocols_descending(capture):
    """Sorted by count descending."""
    capture.packets = [
        _make_packet("Ether", "IP", "TCP"),
        _make_packet("Ether", "IP", "TCP"),
        _make_packet("Ether", "IP", "UDP"),
    ]
    result = capture.sort_network_protocols()
    counts = [count for _, count in result]
    assert counts == sorted(counts, reverse=True)
    assert dict(result) == {"Ether": 3, "IP": 3, "TCP": 2, "UDP": 1}


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