import re

from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


# Common SQL injection signatures (case-insensitive)
SQLI_PATTERNS: list[str] = [
    r"(?i)'\s*or\s*'?\s*\d+\s*'?\s*=\s*'?\s*\d+",   # ' OR 1=1
    r"(?i)\bunion\s+select\b",                       # UNION SELECT
    r"(?i)\bdrop\s+table\b",                         # DROP TABLE
    r"(?i)\binsert\s+into\b",                        # INSERT INTO
    r"(?i)/\*.*?\*/",                                # /* SQL block comment */
    r"(?i)--\s",                                     # -- SQL line comment
    r"(?i)\bxp_cmdshell\b",                          # SQL Server cmd exec
    r"(?i)\bexec(?:ute)?\s*\(",                      # EXEC(...)
]


class Capture:
    DEFAULT_PACKET_COUNT = 50
    DEFAULT_TIMEOUT = 30  # seconds

    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []
        self.threats: list[dict] = []  # accumulated by analyse()

    def capture_traffic(
        self,
        count: int = DEFAULT_PACKET_COUNT,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """
        Capture network traffic from the chosen interface using Scapy.
        Requires root privileges — run with `sudo poetry run tp1`.
        """
        interface = self.interface
        if not interface:
            logger.error("No interface selected, cannot capture traffic")
            return

        logger.info(
            f"Starting capture on {interface} (count={count}, timeout={timeout}s)"
        )
        try:
            self.packets = sniff(iface=interface, count=count, timeout=timeout)
            logger.info(f"Captured {len(self.packets)} packets")
        except PermissionError:
            logger.error(
                "Permission denied — Scapy needs root. Try: sudo poetry run tp1"
            )
            self.packets = []
        except Exception as e:
            logger.error(f"Capture failed: {e}")
            self.packets = []

    def get_all_protocols(self) -> dict[str, int]:
        """Count packets by protocol layer name."""
        counts: dict[str, int] = {}
        for packet in self.packets:
            for layer_class in packet.layers():
                name = layer_class.__name__
                counts[name] = counts.get(name, 0) + 1
        return counts

    def sort_network_protocols(self) -> list[tuple[str, int]]:
        """Sort protocols by packet count, descending."""
        protocols = self.get_all_protocols()
        return sorted(protocols.items(), key=lambda kv: kv[1], reverse=True)

    def _detect_arp_spoofing(self) -> list[dict]:
        """
        Detect ARP spoofing: same IP claimed by multiple MAC addresses
        in ARP reply packets (opcode=2).
        """
        threats: list[dict] = []
        ip_to_macs: dict[str, set[str]] = {}

        for packet in self.packets:
            if not packet.haslayer(ARP):
                continue
            arp = packet[ARP]
            if arp.op != 2:  # only inspect ARP replies
                continue
            ip_to_macs.setdefault(arp.psrc, set()).add(arp.hwsrc)

        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                threats.append(
                    {
                        "attack_type": "ARP Spoofing",
                        "protocol": "ARP",
                        "src_ip": ip,
                        "src_mac": ", ".join(sorted(macs)),
                        "details": (
                            f"IP {ip} claimed by {len(macs)} MACs: "
                            f"{sorted(macs)}"
                        ),
                    }
                )
        return threats

    def _detect_sql_injection(self) -> list[dict]:
        """
        Detect SQL injection patterns in TCP payloads (plaintext HTTP).
        Stops at first match per packet to avoid duplicate threats.
        """
        threats: list[dict] = []

        for packet in self.packets:
            if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
                continue

            payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")

            for pattern in SQLI_PATTERNS:
                match = re.search(pattern, payload)
                if match:
                    src_ip = packet[IP].src if packet.haslayer(IP) else "?"
                    src_mac = (
                        packet[Ether].src if packet.haslayer(Ether) else "?"
                    )
                    threats.append(
                        {
                            "attack_type": "SQL Injection",
                            "protocol": "TCP/HTTP",
                            "src_ip": src_ip,
                            "src_mac": src_mac,
                            "details": f"Pattern matched: {match.group(0)!r}",
                        }
                    )
                    break  # one threat per packet is enough
        return threats

    def analyse(self, protocols: str = "all") -> None:
        """
        Run all attack detectors on captured packets and generate summary.
        Detected threats are accumulated in self.threats for the PDF report.
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.threats = []
        self.threats.extend(self._detect_arp_spoofing())
        self.threats.extend(self._detect_sql_injection())

        if self.threats:
            logger.warning(f"{len(self.threats)} threat(s) detected!")
            for t in self.threats:
                logger.warning(
                    f"  - {t['attack_type']} from {t.get('src_ip', '?')}"
                )
        else:
            logger.info("No suspicious traffic detected — all good")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """Return summary."""
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate a human-readable summary of the analysis:
        - total packet count
        - protocol distribution (sorted)
        - threats list (if any)
        """
        lines: list[str] = []
        total = len(self.packets)
        lines.append(f"Total packets captured: {total}")
        lines.append("")
        lines.append("Protocol distribution:")
        for proto, count in self.sort_network_protocols():
            lines.append(f"  - {proto}: {count}")
        lines.append("")

        if self.threats:
            lines.append(f"{len(self.threats)} suspicious activity detected:")
            for t in self.threats:
                lines.append(
                    f"  - [{t['attack_type']}] {t.get('protocol', '?')} | "
                    f"src_ip={t.get('src_ip', '?')} | "
                    f"src_mac={t.get('src_mac', '?')} | "
                    f"{t.get('details', '')}"
                )
        else:
            lines.append("No suspicious activity detected.")

        return "\n".join(lines)