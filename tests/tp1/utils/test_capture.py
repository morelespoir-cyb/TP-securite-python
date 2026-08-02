import pytest
import subprocess
from unittest.mock import patch, MagicMock

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from src.tp1.utils.capture import Capture


@pytest.fixture
def capture():
    with patch("src.tp1.utils.capture.choose_interface", return_value=""):
        yield Capture()


def _make_packet(*layer_names: str) -> MagicMock:
    layer_classes = [type(name, (), {}) for name in layer_names]
    pkt = MagicMock()
    pkt.layers.return_value = layer_classes
    return pkt


# ---------- init & capture_traffic ----------


def test_capture_init(capture):
    assert capture.interface == ""
    assert capture.summary == ""
    assert capture.packets == []
    assert capture.threats == []
    assert capture.blocked_ips == []



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


# ---------- protocols counting & sorting ----------


def test_get_all_protocols_empty(capture):
    capture.packets = []
    assert capture.get_all_protocols() == {}


def test_get_all_protocols_counts_layers(capture):
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
    capture.packets = []
    assert capture.sort_network_protocols() == []


def test_sort_network_protocols_descending(capture):
    capture.packets = [
        _make_packet("Ether", "IP", "TCP"),
        _make_packet("Ether", "IP", "TCP"),
        _make_packet("Ether", "IP", "UDP"),
    ]
    result = capture.sort_network_protocols()
    counts = [c for _, c in result]
    assert counts == sorted(counts, reverse=True)
    assert dict(result) == {"Ether": 3, "IP": 3, "TCP": 2, "UDP": 1}


# ---------- ARP spoofing detection ----------


def test_detect_arp_spoofing_no_threat(capture):
    """A single ARP reply per IP is normal traffic."""
    pkt = Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff")
    capture.packets = [pkt]
    assert capture._detect_arp_spoofing() == []


def test_detect_arp_spoofing_detected(capture):
    """Same IP claimed by two MACs → spoofing."""
    pkt1 = Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff")
    pkt2 = Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="11:22:33:44:55:66")
    capture.packets = [pkt1, pkt2]
    threats = capture._detect_arp_spoofing()
    assert len(threats) == 1
    assert threats[0]["attack_type"] == "ARP Spoofing"
    assert threats[0]["src_ip"] == "192.168.1.10"
    assert "aa:bb:cc:dd:ee:ff" in threats[0]["src_mac"]
    assert "11:22:33:44:55:66" in threats[0]["src_mac"]


def test_detect_arp_spoofing_ignores_requests(capture):
    """ARP requests (op=1) are not analysed, only replies."""
    pkt = Ether() / ARP(op=1, psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:ff")
    capture.packets = [pkt]
    assert capture._detect_arp_spoofing() == []


# ---------- SQL injection detection ----------


def test_detect_sql_injection_no_threat(capture):
    """Plain HTTP request without SQLi → no threat."""
    pkt = (
        Ether()
        / IP(src="10.0.0.1")
        / TCP()
        / Raw(load=b"GET /index.html HTTP/1.1\r\n\r\n")
    )
    capture.packets = [pkt]
    assert capture._detect_sql_injection() == []


def test_detect_sql_injection_or_pattern(capture):
    """Classic ' OR 1=1 SQLi pattern is caught."""
    pkt = (
        Ether()
        / IP(src="10.0.0.1")
        / TCP()
        / Raw(load=b"POST /login HTTP/1.1\r\nuser=admin' OR 1=1 -- ")
    )
    capture.packets = [pkt]
    threats = capture._detect_sql_injection()
    assert len(threats) == 1
    assert threats[0]["attack_type"] == "SQL Injection"
    assert threats[0]["src_ip"] == "10.0.0.1"


def test_detect_sql_injection_union_select(capture):
    """UNION SELECT pattern is caught."""
    pkt = (
        Ether()
        / IP(src="10.0.0.42")
        / TCP()
        / Raw(load=b"GET /?id=1 UNION SELECT * FROM users-- HTTP/1.1")
    )
    capture.packets = [pkt]
    threats = capture._detect_sql_injection()
    assert len(threats) == 1
    assert threats[0]["src_ip"] == "10.0.0.42"


# ---------- analyse & summary ----------


def test_analyse(capture):
    """analyse orchestrates detectors and writes summary."""
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_detect_arp_spoofing", return_value=[]) as mock_arp,
        patch.object(capture, "_detect_sql_injection", return_value=[]) as mock_sqli,
        patch.object(capture, "_block_attackers") as mock_block,
        patch.object(capture, "_gen_summary", return_value="Test summary") as mock_gen,
    ):
        capture.analyse("tcp")

    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_arp.assert_called_once()
    mock_sqli.assert_called_once()
    mock_block.assert_not_called()  # no threats → no blocking
    mock_gen.assert_called_once()
    assert capture.summary == "Test summary"
    assert capture.threats == []


def test_analyse_collects_threats_and_blocks(capture):
    """When threats exist, block_attackers is called."""
    with (
        patch.object(capture, "_detect_arp_spoofing", return_value=[{"attack_type": "ARP Spoofing", "src_ip": "1.1.1.1"}]),
        patch.object(capture, "_detect_sql_injection", return_value=[{"attack_type": "SQL Injection", "src_ip": "2.2.2.2"}]),
        patch.object(capture, "_block_attackers") as mock_block,
        patch.object(capture, "_gen_summary", return_value=""),
    ):
        capture.analyse("all")

    assert len(capture.threats) == 2
    mock_block.assert_called_once()


def test_get_summary(capture):
    capture.summary = "Test summary"
    assert capture.get_summary() == "Test summary"


def test_gen_summary_no_threats(capture):
    capture.packets = [_make_packet("Ether", "IP", "TCP")]
    capture.threats = []
    result = capture._gen_summary()
    assert "Total packets captured: 1" in result
    assert "TCP: 1" in result
    assert "No suspicious activity" in result


def test_gen_summary_with_threats(capture):
    capture.packets = []
    capture.threats = [
        {
            "attack_type": "ARP Spoofing",
            "protocol": "ARP",
            "src_ip": "192.168.1.10",
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "details": "test",
        }
    ]
    result = capture._gen_summary()
    assert "1 suspicious activity detected" in result
    assert "ARP Spoofing" in result
    assert "192.168.1.10" in result

    # ---------- attacker blocking ----------

def test_block_attackers_dry_run_by_default(capture):
    """Dry-run: no subprocess call, but IPs recorded."""
    capture.threats = [
        {"attack_type": "SQL Injection", "src_ip": "10.0.0.1"},
        {"attack_type": "SQL Injection", "src_ip": "10.0.0.2"},
    ]
    with patch("src.tp1.utils.capture.subprocess.run") as mock_run:
        capture._block_attackers(dry_run=True)
    mock_run.assert_not_called()
    assert sorted(capture.blocked_ips) == ["10.0.0.1", "10.0.0.2"]

def test_block_attackers_real_calls_iptables(capture):
    """Real mode: iptables DROP rule added per unique IP."""
    capture.threats = [
        {"attack_type": "SQL Injection", "src_ip": "10.0.0.1"},
    ]
    with patch("src.tp1.utils.capture.subprocess.run") as mock_run:
        capture._block_attackers(dry_run=False)
    mock_run.assert_called_once()
    args = mock_run.call_args.args[0]
    assert args == ["iptables", "-A", "INPUT", "-s", "10.0.0.1", "-j", "DROP"]
    assert capture.blocked_ips == ["10.0.0.1"]

def test_block_attackers_deduplicates_ips(capture):
    """Same IP in multiple threats → single block."""
    capture.threats = [
        {"attack_type": "SQL Injection", "src_ip": "10.0.0.1"},
        {"attack_type": "SQL Injection", "src_ip": "10.0.0.1"},
        {"attack_type": "SQL Injection", "src_ip": "10.0.0.1"},
    ]
    capture._block_attackers(dry_run=True)
    assert capture.blocked_ips == ["10.0.0.1"]

def test_block_attackers_ignores_unknown_ips(capture):
    """Threats with '?' src_ip are skipped (nothing to block)."""
    capture.threats = [{"attack_type": "SQL Injection", "src_ip": "?"}]
    capture._block_attackers(dry_run=True)
    assert capture.blocked_ips == []

def test_block_attackers_handles_iptables_failure(capture):
    """iptables error is logged, no crash, no IP recorded."""
    capture.threats = [{"attack_type": "SQL Injection", "src_ip": "10.0.0.1"}]
    with patch(
            "src.tp1.utils.capture.subprocess.run",
            side_effect=subprocess.CalledProcessError(
                1, ["iptables"], stderr=b"permission denied"
            ),
    ):
        capture._block_attackers(dry_run=False)
    assert capture.blocked_ips == []