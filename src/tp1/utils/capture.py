from scapy.all import sniff

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    DEFAULT_PACKET_COUNT = 50
    DEFAULT_TIMEOUT = 30  # seconds

    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []  # Will hold the captured Scapy PacketList

    def capture_traffic(
        self,
        count: int = DEFAULT_PACKET_COUNT,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """
        Capture network traffic from the chosen interface using Scapy.

        Stops after `count` packets or `timeout` seconds, whichever comes first.
        Requires root privileges (CAP_NET_RAW) — run with `sudo poetry run tp1`.
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
        """
        Count packets by protocol layer name.

        For each captured packet, walk through its Scapy layers (Ether, IP,
        TCP, etc.) and increment the counter for each layer encountered.
        A single TCP/IP packet contributes to Ether, IP and TCP counts.

        :return: dict mapping protocol name → number of packets
        """
        counts: dict[str, int] = {}
        for packet in self.packets:
            for layer_class in packet.layers():
                name = layer_class.__name__
                counts[name] = counts.get(name, 0) + 1
        return counts

    def sort_network_protocols(self) -> list[tuple[str, int]]:
        """
        Sort protocols by packet count, descending.

        Useful for reporting (most-frequent protocol first) and for the
        graph generation in the PDF report.

        :return: list of (protocol_name, count) tuples sorted desc by count
        """
        protocols = self.get_all_protocols()
        return sorted(protocols.items(), key=lambda kv: kv[1], reverse=True)

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and generate the summary.
        Full detection logic (SQLi, ARP spoofing) comes in Lot 4.
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary