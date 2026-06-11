from unittest.mock import patch, mock_open, MagicMock
from src.tp1.utils.report import Report


def test_report_init():
    # Given
    capture = MagicMock()
    filename = "test.pdf"
    summary = "Test summary"

    # When
    report = Report(capture, filename, summary)

    # Then
    assert report.capture == capture
    assert report.filename == filename
    assert report.title == "TITRE DU RAPPORT"
    assert report.summary == summary
    assert report.array == ""
    assert report.graph == ""


def test_concat_report():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"
    report.array = "Test Array"
    report.graph = "Test Graph"

    # When
    result = report.concat_report()

    # Then
    assert result == "Test TitleTest summaryTest ArrayTest Graph"


def test_save():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"

    # When/Then
    with patch("builtins.open", mock_open()) as mock_file:
        report.save("test.pdf")

        # Verify file was opened with correct name
        mock_file.assert_called_once_with("test.pdf", "w")

        # Verify write was called with the concatenated content
        mock_file().write.assert_called_once_with("Test TitleTest summary")


def test_generate_graph():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")

    # When
    report.generate("graph")

    # Then
    assert report.graph == ""  # Currently returns empty string


def test_generate_array():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert report.array == ""  # Currently returns empty string


def test_generate_invalid_param():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")

    # When
    report.generate("invalid")

    # Then
    assert report.graph == ""
    assert report.array == ""
