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

        :param count: maximum number of packets to capture
        :param timeout: max capture duration in seconds (safety net)
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

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return ""

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
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