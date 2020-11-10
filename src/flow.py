from enum import Enum
from typing import Any

import constants

from features.context.packet_direction import PacketDirection
from features.context import packet_flow_key
from features.flow_bytes import FlowBytes
from features.flag_count import FlagCount
from features.packet_count import PacketCount
from features.packet_length import PacketLength
from features.packet_time import PacketTime
from features.response_time import ResponseTime


class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Any, direction: Enum):
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
            direction (Enum): The direction the packet is going ove the wire.
        """

        (
            self.dest_ip,
            self.src_ip,
            self.src_port,
            self.dest_port,
        ) = packet_flow_key.get_packet_flow_key(packet, direction)

        self.packets = []
        self.latest_timestamp = 0
        self.start_timestamp = 0
        self.flow_interarrival_time = []

    def get_data(self) -> dict:
        """This method obtains the values of the features extracted from each flow.

        Note:
            Only some of the network data plays well together in this list.
            Time-to-live values, window values, and flags cause the data to
            separate out too much.

        Returns:
           list: returns a List of values to be outputted into a csv file.

        """

        flow_bytes = FlowBytes(self)
        flag_count = FlagCount(self)
        packet_count = PacketCount(self)
        packet_length = PacketLength(self)
        packet_time = PacketTime(self)
        response = ResponseTime(self)
        flow_iat = packet_time.get_flow_iat()
        forward_iat = packet_time.get_packet_iat(PacketDirection.FORWARD)
        backward_iat = packet_time.get_packet_iat(PacketDirection.REVERSE)

        data = {
            # Basic IP information
            "src_ip": self.src_ip,
            "dst_ip": self.dest_ip,
            "src_port": self.src_port,
            "dst_port": self.dest_port,
            "protocol": self.protocol,
            # Basic information from packet times
            "timestamp": packet_time.get_time_stamp(),
            "flow_duration": packet_time.get_duration(),
            "flow_byts_s": flow_bytes.get_rate(),
            "flow_pkts_s": packet_count.get_rate(),
            # Count total packets by direction
            "tot_fwd_pkts": packet_count.get_total(PacketDirection.FORWARD),
            "tot_bwd_pkts": packet_count.get_total(PacketDirection.REVERSE),
            # Statistical info obtained from Packet lengths
            "totlen_fwd_pkts": packet_length.get_total(PacketDirection.FORWARD),
            "totlen_bwd_pkts": packet_length.get_total(PacketDirection.REVERSE),
            "fwd_pkt_len_max": packet_length.get_max(PacketDirection.FORWARD),
            "fwd_pkt_len_min": packet_length.get_min(PacketDirection.FORWARD),
            "fwd_pkt_len_mean": packet_length.get_mean(PacketDirection.FORWARD),
            "fwd_pkt_len_std": packet_length.get_std(PacketDirection.FORWARD),
            "bwd_pkt_len_max": packet_length.get_max(PacketDirection.REVERSE),
            "bwd_pkt_len_min": packet_length.get_min(PacketDirection.REVERSE),
            "bwd_pkt_len_mean": packet_length.get_mean(PacketDirection.REVERSE),
            "bwd_pkt_len_std": packet_length.get_std(PacketDirection.REVERSE),
            # Flows Interarrival Time
            "flow_iat_mean": flow_iat["mean"],
            "flow_iat_max": flow_iat["max"],
            "flow_iat_min": flow_iat["min"],
            "flow_iat_std": flow_iat["std"],
            "fwd_iat_tot": forward_iat["total"],
            "fwd_iat_max": forward_iat["max"],
            "fwd_iat_min": forward_iat["min"],
            "fwd_iat_mean": forward_iat["mean"],
            "fwd_iat_std": forward_iat["std"],
            "bwd_iat_tot": backward_iat["total"],
            "bwd_iat_max": backward_iat["max"],
            "bwd_iat_min": backward_iat["min"],
            "bwd_iat_mean": backward_iat["mean"],
            "bwd_iat_std": backward_iat["std"],
            # Flags statistics
            "fwd_psh_flags": flag_count.has_flag("PSH", PacketDirection.FORWARD),
            "bwd_psh_flags": flag_count.has_flag("PSH", PacketDirection.REVERSE),
            "fwd_urg_flags": flag_count.has_flag("URG", PacketDirection.FORWARD),
            "bwd_urg_flags": flag_count.has_flag("URG", PacketDirection.REVERSE),
            "fin_flag_cnt": flag_count.has_flag("FIN"),
            "syn_flag_cnt": flag_count.has_flag("SYN"),
            "rst_flag_cnt": flag_count.has_flag("RST"),
            "psh_flag_cnt": flag_count.has_flag("PSH"),
            "ack_flag_cnt": flag_count.has_flag("ACK"),
            "urg_flag_cnt": flag_count.has_flag("URG"),
            "ece_flag_cnt": flag_count.has_flag("ECE"),
            "cwe_flag_count": flag_count.has_flag("CWR"),
            # Response Time
            "down_up_ratio": packet_count.get_down_up_ratio(),
            "pkt_size_avg": packet_length.get_avg(),
            "fwd_seg_size_avg": packet_length.get_avg(PacketDirection.FORWARD),
            "bwd_seg_size_avg": packet_length.get_avg(PacketDirection.REVERSE),
            "DoH": self.is_doh(),
        }

        return data

    def add_packet(self, packet, direction) -> None:
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be added to a flow
            direction: The direction the packet is going in that flow

        """
        self.packets.append((packet, direction))

        if self.start_timestamp != 0:
            self.flow_interarrival_time.append(
                10e5 * (packet.time - self.latest_timestamp)
            )

        self.latest_timestamp = max([packet.time, self.latest_timestamp])

        if self.start_timestamp == 0:
            self.start_timestamp = packet.time
            self.protocol = packet.proto

    def is_doh(self) -> bool:
        return self.src_ip in constants.DOH_IPS or self.dest_ip in constants.DOH_IPS

    @property
    def duration(self):
        return self.latest_timestamp - self.start_timestamp
