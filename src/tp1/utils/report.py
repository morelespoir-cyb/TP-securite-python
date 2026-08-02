import os
import pygal
from fpdf import FPDF
from fpdf.enums import XPos, YPos

from src.tp1.utils.capture import Capture
from tp1.utils.config import logger


class Report:
    """
    PDF report builder for the TP1 IDS/IPS analysis.

    Output:
    - A real PDF (`filename`) containing: title, summary, bar chart,
      protocols table, and threat list (if any)
    - A companion SVG chart (`chart.svg`) rendered with pygal, suitable
      for embedding elsewhere
    """

    SVG_FILENAME = "chart.svg"

    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "TP1 - IDS/IPS Network Analysis Report"
        self.summary = summary
        self.array: list[tuple[str, int]] = []  # protocol distribution data
        self.graph: str = ""                    # path to the generated SVG

    def concat_report(self) -> str:
        """
        Debug-friendly textual representation of the report (not the PDF
        itself — the PDF is built in `save()`).
        """
        parts = [
            self.title,
            "",
            self.summary,
            "",
            f"Protocols data: {self.array}",
            f"SVG chart: {self.graph}",
        ]
        return "\n".join(parts)

    def generate(self, param: str) -> None:
        """
        Generate either the SVG chart (param='graph') or the table data
        (param='array'). Other values are ignored.
        """
        if param == "graph":
            self._generate_graph()
        elif param == "array":
            self._generate_array()

    def _generate_graph(self) -> None:
        """Render a pygal bar chart of protocol distribution → SVG file."""
        protocols = self.capture.sort_network_protocols()
        chart = pygal.Bar()
        chart.title = "Network protocols distribution"
        for proto, count in protocols:
            chart.add(proto, count)
        chart.render_to_file(self.SVG_FILENAME)
        self.graph = self.SVG_FILENAME
        logger.info(f"SVG chart rendered to {self.SVG_FILENAME}")

    def _generate_array(self) -> None:
        """Populate self.array with sorted protocol counts."""
        self.array = self.capture.sort_network_protocols()

    def save(self, filename: str) -> None:
        """
        Build the final PDF: title + summary + native bar chart + table
        + threats section (if any).
        """
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)

        # --- Title ---
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(
            0, 10, self.title,
            new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C",
        )
        pdf.ln(3)

        # --- Summary ---
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, "Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, self.summary)
        pdf.ln(3)

        # --- Bar chart (native fpdf2) ---
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(
            0, 7, "Protocol distribution (chart)",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )
        self._draw_bar_chart(pdf)
        pdf.ln(5)

        # --- Table ---
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(
            0, 7, "Protocol distribution (table)",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )
        self._draw_table(pdf)

        # --- Threats section ---
        threats = getattr(self.capture, "threats", [])
        if threats:
            pdf.ln(5)
            pdf.set_text_color(180, 0, 0)
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(
                0, 7, f"/!\\ {len(threats)} threat(s) detected",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 9)
            for t in threats:
                pdf.multi_cell(
                    0, 5,
                    f"- [{t.get('attack_type')}] "
                    f"proto={t.get('protocol', '?')} | "
                    f"src_ip={t.get('src_ip', '?')} | "
                    f"src_mac={t.get('src_mac', '?')}\n"
                    f"  {t.get('details', '')}",
                )
                # --- Blocking actions section ---
                blocked = getattr(self.capture, "blocked_ips", [])
                if blocked:
                    pdf.ln(5)
                    pdf.set_text_color(0, 100, 0)
                    pdf.set_font("Helvetica", "B", 12)
                    mode = (
                        "REAL"
                        if os.environ.get("TP1_BLOCK_ATTACKERS", "0") == "1"
                        else "DRY-RUN"
                    )
                    pdf.cell(
                        0, 7, f"Blocking actions ({mode}) - {len(blocked)} IP(s)",
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
                    )
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font("Helvetica", "", 10)
                    for ip in blocked:
                        pdf.cell(
                            0, 5, f"  - {ip}",
                            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
                        )

        pdf.output(self.filename)
        logger.info(f"PDF report saved to {self.filename}")

    def _draw_bar_chart(self, pdf: FPDF) -> None:
        """Draw a horizontal bar chart using fpdf2 primitives."""
        if not self.array:
            pdf.set_font("Helvetica", "I", 10)
            pdf.cell(
                0, 6, "(no data)",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
            return

        max_count = max(c for _, c in self.array)
        max_chart_width = 100  # mm
        bar_height = 6  # mm

        pdf.set_font("Helvetica", "", 10)
        for proto, count in self.array:
            y_start = pdf.get_y()
            # Protocol name
            pdf.cell(35, bar_height, proto, border=0)
            # Bar rectangle
            bar_x = pdf.get_x()
            bar_w = (count / max_count) * max_chart_width if max_count else 0
            pdf.set_fill_color(70, 130, 180)
            pdf.rect(bar_x, y_start + 1, bar_w, bar_height - 2, "F")
            # Count label after the bar
            pdf.set_xy(bar_x + bar_w + 3, y_start)
            pdf.cell(
                15, bar_height, str(count),
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )

    def _draw_table(self, pdf: FPDF) -> None:
        """Draw a 2-column table: Protocol | Packet count."""
        # Header row
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(220, 220, 220)
        pdf.cell(60, 7, "Protocol", border=1, fill=True)
        pdf.cell(
            40, 7, "Packet count", border=1, fill=True,
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )
        # Data rows
        pdf.set_font("Helvetica", "", 10)
        if not self.array:
            pdf.cell(
                100, 6, "(no data)", border=1,
                new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C",
            )
            return
        for proto, count in self.array:
            pdf.cell(60, 6, proto, border=1)
            pdf.cell(
                40, 6, str(count), border=1,
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )