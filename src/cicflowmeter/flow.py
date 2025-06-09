from scapy.packet import Packet

from . import constants
from .features.context import PacketDirection, get_packet_flow_key
from .features.flag_count import FlagCount
from .features.flow_bytes import FlowBytes
from .features.packet_count import PacketCount
from .features.packet_length import PacketLength
from .features.packet_time import PacketTime
from .utils import get_statistics


class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Packet, direction: PacketDirection):
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
            direction (Enum): The direction the packet is going ove the wire.
        """

        (
            self.src_ip,
            self.dest_ip,
            self.src_port,
            self.dest_port,
        ) = get_packet_flow_key(packet, direction)

        # Initialize flow properties with the first packet
        self.packets = [(packet, direction)]  # Add the first packet
        self.flow_interarrival_time = []
        self.start_timestamp = packet.time
        self.latest_timestamp = packet.time  # Initialize latest_timestamp too
        self.protocol = packet.proto

        # Initialize window sizes
        self.init_window_size = {PacketDirection.FORWARD: 0, PacketDirection.REVERSE: 0}
        if "TCP" in packet:
            # Set initial window size based on the first packet's direction
            self.init_window_size[direction] = packet["TCP"].window

        # Initialize active/idle tracking
        self.start_active = packet.time
        self.last_active = 0
        self.active = []
        self.idle = []

        self.forward_bulk_last_timestamp = 0
        self.forward_bulk_start_tmp = 0
        self.forward_bulk_count = 0
        self.forward_bulk_count_tmp = 0
        self.forward_bulk_duration = 0
        self.forward_bulk_packet_count = 0
        self.forward_bulk_size = 0
        self.forward_bulk_size_tmp = 0
        self.backward_bulk_last_timestamp = 0
        self.backward_bulk_start_tmp = 0
        self.backward_bulk_count = 0
        self.backward_bulk_count_tmp = 0
        self.backward_bulk_duration = 0
        self.backward_bulk_packet_count = 0
        self.backward_bulk_size = 0
        self.backward_bulk_size_tmp = 0

    def get_data(self, include_fields=None) -> dict:
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
        flow_iat = get_statistics(self.flow_interarrival_time)
        forward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.FORWARD)
        )
        backward_iat = get_statistics(
            packet_time.get_packet_iat(PacketDirection.REVERSE)
        )
        active_stat = get_statistics(self.active)
        idle_stat = get_statistics(self.idle)

        data = {
            # Basic IP information
            "src_ip": self.src_ip,
            "dst_ip": self.dest_ip,
            "src_port": self.src_port,
            "dst_port": self.dest_port,
            "protocol": self.protocol,
            # Basic information from packet times
            "timestamp": packet_time.get_timestamp(),
            "flow_duration": packet_time.get_duration(),
            "flow_byts_s": flow_bytes.get_rate(),
            "flow_pkts_s": packet_count.get_rate(),
            "fwd_pkts_s": packet_count.get_rate(PacketDirection.FORWARD),
            "bwd_pkts_s": packet_count.get_rate(PacketDirection.REVERSE),
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
            "pkt_len_max": packet_length.get_max(),
            "pkt_len_min": packet_length.get_min(),
            "pkt_len_mean": packet_length.get_mean(),
            "pkt_len_std": packet_length.get_std(),
            "pkt_len_var": packet_length.get_var(),
            "fwd_header_len": flow_bytes.get_forward_header_bytes(),
            "bwd_header_len": flow_bytes.get_reverse_header_bytes(),
            "fwd_seg_size_min": flow_bytes.get_min_forward_header_bytes(),
            "fwd_act_data_pkts": packet_count.has_payload(PacketDirection.FORWARD),
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
            "fwd_psh_flags": flag_count.count("PSH", PacketDirection.FORWARD),
            "bwd_psh_flags": flag_count.count("PSH", PacketDirection.REVERSE),
            "fwd_urg_flags": flag_count.count("URG", PacketDirection.FORWARD),
            "bwd_urg_flags": flag_count.count("URG", PacketDirection.REVERSE),
            "fin_flag_cnt": flag_count.count("FIN"),
            "syn_flag_cnt": flag_count.count("SYN"),
            "rst_flag_cnt": flag_count.count("RST"),
            "psh_flag_cnt": flag_count.count("PSH"),
            "ack_flag_cnt": flag_count.count("ACK"),
            "urg_flag_cnt": flag_count.count("URG"),
            "ece_flag_cnt": flag_count.count("ECE"),
            # Response Time
            "down_up_ratio": packet_count.get_down_up_ratio(),
            "pkt_size_avg": packet_length.get_avg(),
            "init_fwd_win_byts": self.init_window_size[PacketDirection.FORWARD],
            "init_bwd_win_byts": self.init_window_size[PacketDirection.REVERSE],
            "active_max": active_stat["max"],
            "active_min": active_stat["min"],
            "active_mean": active_stat["mean"],
            "active_std": active_stat["std"],
            "idle_max": idle_stat["max"],
            "idle_min": idle_stat["min"],
            "idle_mean": idle_stat["mean"],
            "idle_std": idle_stat["std"],
            "fwd_byts_b_avg": flow_bytes.get_bytes_per_bulk(PacketDirection.FORWARD),
            "fwd_pkts_b_avg": flow_bytes.get_packets_per_bulk(PacketDirection.FORWARD),
            "bwd_byts_b_avg": flow_bytes.get_bytes_per_bulk(PacketDirection.REVERSE),
            "bwd_pkts_b_avg": flow_bytes.get_packets_per_bulk(PacketDirection.REVERSE),
            "fwd_blk_rate_avg": flow_bytes.get_bulk_rate(PacketDirection.FORWARD),
            "bwd_blk_rate_avg": flow_bytes.get_bulk_rate(PacketDirection.REVERSE),
        }

        # Duplicated features
        data["fwd_seg_size_avg"] = data["fwd_pkt_len_mean"]
        data["bwd_seg_size_avg"] = data["bwd_pkt_len_mean"]
        data["cwr_flag_count"] = data["fwd_urg_flags"]
        data["subflow_fwd_pkts"] = data["tot_fwd_pkts"]
        data["subflow_bwd_pkts"] = data["tot_bwd_pkts"]
        data["subflow_fwd_byts"] = data["totlen_fwd_pkts"]
        data["subflow_bwd_byts"] = data["totlen_bwd_pkts"]

        if include_fields is not None:
            data = {k: v for k, v in data.items() if k in include_fields}

        return data

    def add_packet(self, packet: Packet, direction: PacketDirection) -> None:
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be added to a flow
            direction: The direction the packet is going in that flow

        """
        self.packets.append((packet, direction))

        # Calculate interarrival time using the previous latest_timestamp
        # This check prevents adding a 0 IAT for the very first packet added after init
        if len(self.packets) > 1:
            self.flow_interarrival_time.append(packet.time - self.latest_timestamp)

        # Update latest timestamp
        self.latest_timestamp = max(packet.time, self.latest_timestamp)

        # Update flow bulk and subflow stats
        self.update_flow_bulk(packet, direction)
        self.update_subflow(packet)

        # Update initial window size if not already set for this direction
        if "TCP" in packet and self.init_window_size[direction] == 0:
            self.init_window_size[direction] = packet["TCP"].window

        # Note: start_timestamp and protocol are set in __init__

    def update_subflow(self, packet: Packet):
        """Update subflow

        Args:
            packet: Packet to be parse as subflow

        """
        last_timestamp = (
            self.latest_timestamp if self.latest_timestamp != 0 else packet.time
        )
        if (packet.time - last_timestamp) > constants.CLUMP_TIMEOUT:
            self.update_active_idle(packet.time - last_timestamp)

    def update_active_idle(self, current_time):
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be update active time

        """
        if (current_time - self.last_active) > constants.ACTIVE_TIMEOUT:
            duration = abs(self.last_active - self.start_active)
            if duration > 0:
                self.active.append(duration)
            self.idle.append(current_time - self.last_active)
            self.start_active = current_time
            self.last_active = current_time
        else:
            self.last_active = current_time

    def update_flow_bulk(self, packet: Packet, direction: PacketDirection):
        """Update bulk flow

        Args:
            packet: Packet to be parse as bulk

        """
        payload_size = len(PacketCount.get_payload(packet))
        if payload_size == 0:
            return
        if direction == PacketDirection.FORWARD:
            if self.backward_bulk_last_timestamp > self.forward_bulk_start_tmp:
                self.forward_bulk_start_tmp = 0
            if self.forward_bulk_start_tmp == 0:
                self.forward_bulk_start_tmp = packet.time
                self.forward_bulk_last_timestamp = packet.time
                self.forward_bulk_count_tmp = 1
                self.forward_bulk_size_tmp = payload_size
            else:
                if (
                    packet.time - self.forward_bulk_last_timestamp
                ) > constants.CLUMP_TIMEOUT:
                    self.forward_bulk_start_tmp = packet.time
                    self.forward_bulk_last_timestamp = packet.time
                    self.forward_bulk_count_tmp = 1
                    self.forward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.forward_bulk_count_tmp += 1
                    self.forward_bulk_size_tmp += payload_size
                    if self.forward_bulk_count_tmp == constants.BULK_BOUND:
                        self.forward_bulk_count += 1
                        self.forward_bulk_packet_count += self.forward_bulk_count_tmp
                        self.forward_bulk_size += self.forward_bulk_size_tmp
                        self.forward_bulk_duration += (
                            packet.time - self.forward_bulk_start_tmp
                        )
                    elif self.forward_bulk_count_tmp > constants.BULK_BOUND:
                        self.forward_bulk_packet_count += 1
                        self.forward_bulk_size += payload_size
                        self.forward_bulk_duration += (
                            packet.time - self.forward_bulk_last_timestamp
                        )
                    self.forward_bulk_last_timestamp = packet.time
        else:
            if self.forward_bulk_last_timestamp > self.backward_bulk_start_tmp:
                self.backward_bulk_start_tmp = 0
            if self.backward_bulk_start_tmp == 0:
                self.backward_bulk_start_tmp = packet.time
                self.backward_bulk_last_timestamp = packet.time
                self.backward_bulk_count_tmp = 1
                self.backward_bulk_size_tmp = payload_size
            else:
                if (
                    packet.time - self.backward_bulk_last_timestamp
                ) > constants.CLUMP_TIMEOUT:
                    self.backward_bulk_start_tmp = packet.time
                    self.backward_bulk_last_timestamp = packet.time
                    self.backward_bulk_count_tmp = 1
                    self.backward_bulk_size_tmp = payload_size
                else:  # Add to bulk
                    self.backward_bulk_count_tmp += 1
                    self.backward_bulk_size_tmp += payload_size
                    if self.backward_bulk_count_tmp == constants.BULK_BOUND:
                        self.backward_bulk_count += 1
                        self.backward_bulk_packet_count += self.backward_bulk_count_tmp
                        self.backward_bulk_size += self.backward_bulk_size_tmp
                        self.backward_bulk_duration += (
                            packet.time - self.backward_bulk_start_tmp
                        )
                    elif self.backward_bulk_count_tmp > constants.BULK_BOUND:
                        self.backward_bulk_packet_count += 1
                        self.backward_bulk_size += payload_size
                        self.backward_bulk_duration += (
                            packet.time - self.backward_bulk_last_timestamp
                        )
                    self.backward_bulk_last_timestamp = packet.time

    @property
    def duration(self):
        return self.latest_timestamp - self.start_timestamp
