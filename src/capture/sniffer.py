"""
Packet Capture Module using Scapy
Supports both live capture and PCAP file replay
"""

import asyncio
from typing import AsyncGenerator, Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import structlog

from src.config.settings import Settings

logger = structlog.get_logger()


class PacketSniffer:
    """
    Async packet capture using Scapy.
    Supports live capture and PCAP file replay.
    """

    def __init__(self, config: Settings):
        """
        Initialize packet sniffer.

        Args:
            config: Application settings
        """
        self.config = config
        self.interface = config.network_interface
        self.is_running = False
        self.packet_count = 0

    async def capture_stream(
        self,
        batch_size: int = 10,
        timeout: Optional[float] = None
    ) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """
        Stream packets in batches (async generator).

        Args:
            batch_size: Number of packets per batch
            timeout: Optional timeout for capture

        Yields:
            Batches of packet dictionaries
        """
        self.is_running = True

        if self.config.enable_live_capture:
            async for batch in self._capture_live(batch_size, timeout):
                yield batch
        else:
            async for batch in self._replay_pcap(batch_size):
                yield batch

    async def _capture_live(
        self,
        batch_size: int,
        timeout: Optional[float]
    ) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """
        Live packet capture from network interface.

        Args:
            batch_size: Number of packets per batch
            timeout: Optional timeout

        Yields:
            Batches of packet dictionaries
        """
        try:
            # Import scapy (lazy import to avoid import errors if not installed)
            from scapy.all import sniff, Dot11

            logger.info(
                "Starting live packet capture",
                interface=self.interface,
                batch_size=batch_size
            )

            batch = []
            start_time = asyncio.get_event_loop().time()

            def packet_handler(pkt):
                """Callback for each captured packet"""
                nonlocal batch

                try:
                    packet_data = self._parse_packet(pkt)
                    if packet_data:
                        batch.append(packet_data)
                        self.packet_count += 1

                except Exception as e:
                    logger.warning("Failed to parse packet", error=str(e))

            while self.is_running:
                if timeout and (asyncio.get_event_loop().time() - start_time) > timeout:
                    break

                # Capture packets in thread pool (scapy is blocking)
                captured = await asyncio.to_thread(
                    sniff,
                    iface=self.interface,
                    prn=packet_handler,
                    count=batch_size,
                    timeout=1,  # 1 second timeout per sniff call
                    monitor=self.config.promiscuous_mode
                )

                if batch:
                    yield batch.copy()
                    batch.clear()

                # Small delay to prevent CPU spinning
                await asyncio.sleep(0.01)

        except PermissionError:
            logger.error(
                "Permission denied for packet capture. Run with sudo or set capabilities.",
                interface=self.interface
            )
            self.is_running = False

        except Exception as e:
            logger.error("Live capture failed", error=str(e), interface=self.interface)
            self.is_running = False

    async def _replay_pcap(
        self,
        batch_size: int
    ) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """
        Replay packets from PCAP files.

        Args:
            batch_size: Number of packets per batch

        Yields:
            Batches of packet dictionaries
        """
        try:
            from scapy.all import rdpcap

            pcap_dir = Path(self.config.pcap_directory)
            pcap_files = list(pcap_dir.glob("*.pcap")) + list(pcap_dir.glob("*.pcapng"))

            if not pcap_files:
                logger.warning("No PCAP files found", directory=str(pcap_dir))
                return

            logger.info(
                "Replaying PCAP files",
                count=len(pcap_files),
                directory=str(pcap_dir)
            )

            for pcap_file in pcap_files:
                if not self.is_running:
                    break

                logger.info("Loading PCAP file", file=str(pcap_file))

                # Load PCAP in thread pool
                packets = await asyncio.to_thread(rdpcap, str(pcap_file))

                batch = []
                for pkt in packets:
                    if not self.is_running:
                        break

                    try:
                        packet_data = self._parse_packet(pkt)
                        if packet_data:
                            batch.append(packet_data)
                            self.packet_count += 1

                            if len(batch) >= batch_size:
                                yield batch.copy()
                                batch.clear()

                                # Simulate real-time replay
                                await asyncio.sleep(0.01)

                    except Exception as e:
                        logger.warning("Failed to parse packet from PCAP", error=str(e))

                # Yield remaining packets
                if batch:
                    yield batch

        except Exception as e:
            logger.error("PCAP replay failed", error=str(e))
            self.is_running = False

    def _parse_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """
        Parse Scapy packet into dictionary format.

        Args:
            pkt: Scapy packet object

        Returns:
            Packet data dictionary or None if parsing fails
        """
        try:
            from scapy.all import Dot11, Ether, IP, TCP, UDP, ARP, DNS

            packet_data = {
                'packet_id': f"pkt_{self.packet_count}",
                'timestamp': datetime.utcnow(),
                'size': len(pkt),
                'frame_type': 'Data',
            }

            # Parse WiFi (802.11) packets
            if pkt.haslayer(Dot11):
                dot11 = pkt[Dot11]
                packet_data['src_mac'] = dot11.addr2 or '00:00:00:00:00:00'
                packet_data['dst_mac'] = dot11.addr1 or '00:00:00:00:00:00'

                # Frame type
                if dot11.type == 0:
                    packet_data['frame_type'] = 'Management'
                elif dot11.type == 1:
                    packet_data['frame_type'] = 'Control'
                elif dot11.type == 2:
                    packet_data['frame_type'] = 'Data'

                # RSSI (if available in RadioTap)
                if hasattr(pkt, 'dBm_AntSignal'):
                    packet_data['rssi'] = pkt.dBm_AntSignal

            # Parse Ethernet packets (for wired or non-monitor mode)
            elif pkt.haslayer(Ether):
                ether = pkt[Ether]
                packet_data['src_mac'] = ether.src
                packet_data['dst_mac'] = ether.dst

            else:
                # Unknown link layer
                return None

            # Parse IP layer
            if pkt.haslayer(IP):
                ip = pkt[IP]
                packet_data['src_ip'] = ip.src
                packet_data['dst_ip'] = ip.dst
                packet_data['protocol'] = ip.proto

                # Parse TCP
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    packet_data['port_src'] = tcp.sport
                    packet_data['port_dst'] = tcp.dport
                    packet_data['protocol'] = 'TCP'

                # Parse UDP
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    packet_data['port_src'] = udp.sport
                    packet_data['port_dst'] = udp.dport
                    packet_data['protocol'] = 'UDP'

            # Parse ARP
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                packet_data['protocol'] = 'ARP'
                packet_data['arp_op'] = arp.op  # 1=request, 2=reply
                packet_data['arp_src_ip'] = arp.psrc
                packet_data['arp_dst_ip'] = arp.pdst

            # Parse DNS
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                packet_data['protocol'] = 'DNS'
                if dns.qr == 0:  # Query
                    packet_data['dns_query'] = dns.qd.qname.decode() if dns.qd else None
                else:  # Response
                    packet_data['dns_response'] = True

            return packet_data

        except Exception as e:
            logger.debug("Packet parsing error", error=str(e))
            return None

    def stop(self) -> None:
        """Stop packet capture"""
        self.is_running = False
        logger.info("Packet capture stopped", total_packets=self.packet_count)

    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics"""
        return {
            'is_running': self.is_running,
            'total_packets': self.packet_count,
            'interface': self.interface,
            'mode': 'live' if self.config.enable_live_capture else 'replay'
        }
