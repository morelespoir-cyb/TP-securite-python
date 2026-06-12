import os
from unittest.mock import MagicMock

from src.tp1.utils.report import Report


def test_report_init():
    capture = MagicMock()
    report = Report(capture, "test.pdf", "Test summary")
    assert report.capture == capture
    assert report.filename == "test.pdf"
    assert report.summary == "Test summary"
    assert report.array == []
    assert report.graph == ""
    assert report.title.startswith("TP1")


def test_concat_report_combines_parts():
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.array = [("TCP", 5)]
    report.graph = "chart.svg"
    result = report.concat_report()
    assert "Test summary" in result
    assert "TCP" in result
    assert "chart.svg" in result


def test_generate_array_populates_data():
    capture = MagicMock()
    capture.sort_network_protocols.return_value = [("TCP", 5), ("UDP", 3)]
    report = Report(capture, "report.pdf", "summary")
    report.generate("array")
    assert report.array == [("TCP", 5), ("UDP", 3)]


def test_generate_invalid_param_is_noop():
    report = Report(MagicMock(), "report.pdf", "summary")
    report.generate("invalid")
    assert report.array == []
    assert report.graph == ""


def test_generate_graph_creates_svg(tmp_path, monkeypatch):
    """pygal renders chart.svg next to the working directory."""
    monkeypatch.chdir(tmp_path)
    capture = MagicMock()
    capture.sort_network_protocols.return_value = [("TCP", 5), ("UDP", 3)]
    report = Report(capture, "report.pdf", "summary")
    report.generate("graph")
    assert report.graph == "chart.svg"
    svg_path = tmp_path / "chart.svg"
    assert svg_path.exists()
    # Quick sanity check: pygal SVG files start with <?xml ...?>
    assert svg_path.read_text(encoding="utf-8").startswith("<?xml")


def test_save_creates_real_pdf(tmp_path):
    """save() produces a valid PDF (magic bytes %PDF-)."""
    capture = MagicMock()
    capture.sort_network_protocols.return_value = [("TCP", 5), ("UDP", 3)]
    capture.threats = []
    filename = str(tmp_path / "report.pdf")
    report = Report(capture, filename, "Test summary")
    report.generate("array")
    report.save(filename)

    assert os.path.exists(filename)
    with open(filename, "rb") as f:
        header = f.read(5)
    assert header == b"%PDF-"


def test_save_with_threats_includes_threats_section(tmp_path):
    """When threats exist, the PDF is generated without errors."""
    capture = MagicMock()
    capture.sort_network_protocols.return_value = [("TCP", 1)]
    capture.threats = [
        {
            "attack_type": "ARP Spoofing",
            "protocol": "ARP",
            "src_ip": "192.168.1.10",
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "details": "IP claimed by multiple MACs",
        }
    ]
    filename = str(tmp_path / "report.pdf")
    report = Report(capture, filename, "Test summary")
    report.generate("array")
    report.save(filename)

    assert os.path.exists(filename)
    # File should be larger than the empty case because of the threats section
    assert os.path.getsize(filename) > 1000


def test_save_empty_data_does_not_crash(tmp_path):
    """No protocols + no threats → PDF still generated cleanly."""
    capture = MagicMock()
    capture.sort_network_protocols.return_value = []
    capture.threats = []
    filename = str(tmp_path / "report.pdf")
    report = Report(capture, filename, "Empty summary")
    report.generate("array")
    report.save(filename)
    assert os.path.exists(filename)