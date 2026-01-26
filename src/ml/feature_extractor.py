"""
ML Feature Extraction Module
Extracts features from network packets for threat detection
"""

import math
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict, deque
from src.models.network import PacketFeatures
from src.config.settings import Settings
import structlog

logger = structlog.get_logger()


class FeatureExtractor:
    """
    Extracts ML features from network packets.
    Maintains state for flow-level and statistical features.
    """

    def __init__(self, config: Settings, window_size: int = 100):
        """
        Initialize feature extractor.

        Args:
            config: Application settings
            window_size: Number of packets to consider for statistical features
        """
        self.config = config
        self.window_size = window_size

        # Flow tracking (src_mac -> flow_data)
        self.flows: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'packets': deque(maxlen=window_size),
            'start_time': None,
            'packet_count': 0,
            'byte_count': 0,
            'unique_dst_ips': set(),
            'unique_dst_macs': set(),
            'unique_ports': set(),
            'last_packet_time': None,
        })

    async def extract(self, packet_data: Dict[str, Any]) -> PacketFeatures:
        """
        Extract features from a single packet.

        Args:
            packet_data: Raw packet data dictionary

        Returns:
            PacketFeatures instance with extracted features
        """
        try:
            # Extract basic packet-level features
            src_mac = packet_data.get('src_mac', '00:00:00:00:00:00')
            dst_mac = packet_data.get('dst_mac', '00:00:00:00:00:00')
            packet_size = packet_data.get('size', 0)
            timestamp = packet_data.get('timestamp', datetime.utcnow())

            # Get flow data
            flow_key = src_mac
            flow = self.flows[flow_key]

            # Initialize flow if first packet
            if flow['start_time'] is None:
                flow['start_time'] = timestamp

            # Calculate inter-arrival time
            inter_arrival_time = None
            if flow['last_packet_time']:
                delta = (timestamp - flow['last_packet_time']).total_seconds() * 1000  # ms
                inter_arrival_time = delta

            flow['last_packet_time'] = timestamp

            # Update flow statistics
            flow['packet_count'] += 1
            flow['byte_count'] += packet_size
            flow['packets'].append(packet_size)

            # Track unique destinations
            if 'dst_ip' in packet_data:
                flow['unique_dst_ips'].add(packet_data['dst_ip'])
            flow['unique_dst_macs'].add(dst_mac)

            if 'port_dst' in packet_data:
                flow['unique_ports'].add(packet_data['port_dst'])

            # Calculate flow duration
            flow_duration = None
            if flow['start_time']:
                flow_duration = (timestamp - flow['start_time']).total_seconds()

            # Calculate rates
            packet_rate = None
            byte_rate = None
            if flow_duration and flow_duration > 0:
                packet_rate = flow['packet_count'] / flow_duration
                byte_rate = flow['byte_count'] / flow_duration

            # Calculate statistical features
            packet_sizes = list(flow['packets'])
            mean_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0

            # Standard deviation
            std_packet_size = 0.0
            if len(packet_sizes) > 1:
                variance = sum((x - mean_packet_size) ** 2 for x in packet_sizes) / len(packet_sizes)
                std_packet_size = math.sqrt(variance)

            # Entropy calculations
            packet_size_entropy = self._calculate_entropy(packet_sizes)
            dst_address_entropy = self._calculate_set_entropy(flow['unique_dst_macs'])

            # Create PacketFeatures instance
            features = PacketFeatures(
                frame_type=packet_data.get('frame_type', 'Data'),
                src_mac=src_mac,
                dst_mac=dst_mac,
                packet_size=packet_size,
                rssi=packet_data.get('rssi'),
                protocol=packet_data.get('protocol', 'Unknown'),
                port_src=packet_data.get('port_src'),
                port_dst=packet_data.get('port_dst'),
                timestamp=timestamp,
                inter_arrival_time=inter_arrival_time,
                packet_rate=packet_rate,
                byte_rate=byte_rate,
                flow_duration=flow_duration,
                mean_packet_size=mean_packet_size,
                std_packet_size=std_packet_size,
                packet_size_entropy=packet_size_entropy,
                dst_address_entropy=dst_address_entropy,
                unique_src_ips=1,  # Single source in this flow
                unique_dst_ips=len(flow['unique_dst_ips']),
                unique_src_ports=1,
                unique_dst_ports=len(flow['unique_ports']),
                raw_packet_id=packet_data.get('packet_id')
            )

            return features

        except Exception as e:
            logger.error("Feature extraction failed", error=str(e), packet_data=packet_data)
            # Return minimal features on error
            return PacketFeatures(
                frame_type='Unknown',
                src_mac=packet_data.get('src_mac', '00:00:00:00:00:00'),
                dst_mac=packet_data.get('dst_mac', '00:00:00:00:00:00'),
                packet_size=packet_data.get('size', 0),
                protocol='Unknown',
                timestamp=packet_data.get('timestamp', datetime.utcnow())
            )

    def _calculate_entropy(self, values: List[float]) -> float:
        """
        Calculate Shannon entropy of a list of values.

        Args:
            values: List of numeric values

        Returns:
            Entropy value (0 = no randomness, higher = more random)
        """
        if not values:
            return 0.0

        # Count occurrences
        counts: Dict[float, int] = defaultdict(int)
        for val in values:
            counts[val] += 1

        # Calculate probabilities and entropy
        total = len(values)
        entropy = 0.0

        for count in counts.values():
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)

        return entropy

    def _calculate_set_entropy(self, value_set: set) -> float:
        """
        Calculate entropy based on set size (diversity measure).

        Args:
            value_set: Set of unique values

        Returns:
            Entropy value
        """
        size = len(value_set)
        if size <= 1:
            return 0.0

        # Normalized entropy based on diversity
        return math.log2(size)

    def reset_flow(self, src_mac: str) -> None:
        """Reset flow statistics for a specific source MAC"""
        if src_mac in self.flows:
            del self.flows[src_mac]

    def reset_all_flows(self) -> None:
        """Reset all flow statistics"""
        self.flows.clear()

    def get_active_flows_count(self) -> int:
        """Get number of active flows being tracked"""
        return len(self.flows)

    def cleanup_old_flows(self, max_age_seconds: int = 300) -> int:
        """
        Remove flows that haven't seen packets in a while.

        Args:
            max_age_seconds: Maximum age in seconds

        Returns:
            Number of flows removed
        """
        now = datetime.utcnow()
        to_remove = []

        for flow_key, flow_data in self.flows.items():
            last_time = flow_data.get('last_packet_time')
            if last_time:
                age = (now - last_time).total_seconds()
                if age > max_age_seconds:
                    to_remove.append(flow_key)

        for key in to_remove:
            del self.flows[key]

        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} old flows")

        return len(to_remove)
