from scapy.layers.inet import IP

from .context import PacketDirection
from .packet_time import PacketTime


class FlowBytes:
    """Extracts features from the traffic related to the bytes in a flow"""

    def __init__(self, flow):
        self.flow = flow

    def get_bytes(self) -> int:
        """Calculates the amount bytes being transfered.

        Returns:
            int: The amount of bytes.

        """
        return sum(len(packet) for packet, _ in self.flow.packets)

    def get_rate(self) -> float:
        """Calculates the rate of the bytes being transfered in the current flow.

        Returns:
            float: The bytes/sec sent.

        """
        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            rate = 0
        else:
            rate = self.get_bytes() / duration

        return rate

    def get_bytes_sent(self) -> int:
        """Calculates the amount bytes sent from the machine being used to run DoHlyzer.

        Returns:
            int: The amount of bytes.

        """
        return sum(
            len(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.FORWARD
        )

    def get_sent_rate(self) -> float:
        """Calculates the rate of the bytes being sent in the current flow.

        Returns:
            float: The bytes/sec sent.

        """
        sent = self.get_bytes_sent()
        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            rate = -1
        else:
            rate = sent / duration

        return rate

    def get_bytes_received(self) -> int:
        """Calculates the amount bytes received.

        Returns:
            int: The amount of bytes.

        """
        packets = self.flow.packets

        return sum(
            len(packet)
            for packet, direction in packets
            if direction == PacketDirection.REVERSE
        )

    def get_received_rate(self) -> float:
        """Calculates the rate of the bytes being received in the current flow.

        Returns:
            float: The bytes/sec received.

        """
        received = self.get_bytes_received()
        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            rate = -1
        else:
            rate = received / duration

        return rate

    def get_forward_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the same direction as the flow.

        Returns:
            int: The amount of bytes.

        """
        return sum(
            self._header_size(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.FORWARD
        )

    def get_forward_rate(self) -> int:
        """Calculates the rate of the bytes being going forward
        in the current flow.

        Returns:
            float: The bytes/sec forward.

        """
        forward = self.get_forward_header_bytes()
        duration = PacketTime(self.flow).get_duration()

        if duration > 0:
            rate = forward / duration
        else:
            rate = -1

        return rate

    def _header_size(self, packet):
        # Calculate IP header size if IP layer exists
        if IP in packet:
            ihl = packet[IP].ihl
            # Handle case where ihl might be None (though ideally shouldn't happen with proper packet construction)
            if ihl is None:
                # Default to 20 bytes (standard IPv4 header without options)
                # TODO: Consider logging a warning here
                return 20
            else:
                return ihl * 4
        else:
            # No IP layer found
            return 0

    def get_reverse_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the opposite direction as the flow.

        Returns:
            int: The amount of bytes.

        """
        if not self.flow.packets:
            return 0

        return sum(
            self._header_size(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.REVERSE
        )

    def get_min_forward_header_bytes(self) -> int:
        """Calculates the amount of header bytes in the header sent in the opposite direction as the flow.

        Returns:
            int: The amount of bytes.

        """
        if not self.flow.packets:
            return 0

        return min(
            self._header_size(packet)
            for packet, direction in self.flow.packets
            if direction == PacketDirection.FORWARD
        )

    def get_reverse_rate(self) -> int:
        """Calculates the rate of the bytes being going reverse
        in the current flow.

        Returns:
            float: The bytes/sec reverse.

        """
        reverse = self.get_reverse_header_bytes()
        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            rate = -1
        else:
            rate = reverse / duration

        return rate

    def get_header_in_out_ratio(self) -> float:
        """Calculates the ratio of foward traffic over reverse traffic.

        Returns:
            float: The ratio over reverse traffic.
            If the reverse header bytes is 0 this returns -1 to avoid
            a possible division by 0.

        """
        reverse_header_bytes = self.get_reverse_header_bytes()
        forward_header_bytes = self.get_forward_header_bytes()

        ratio = -1
        if reverse_header_bytes != 0:
            ratio = forward_header_bytes / reverse_header_bytes

        return ratio

    def get_initial_ttl(self) -> int:
        """Obtains the initial time-to-live value.

        Returns:
            int: The initial ttl value in seconds.

        """
        return [packet["IP"].ttl for packet, _ in self.flow.packets][0]

    def get_bytes_per_bulk(self, direction: PacketDirection) -> float:
        """Calculates packet bytes per bulk

        Returns:
            float: bytes per bulk ratio.

        """
        if direction is PacketDirection.FORWARD and self.flow.forward_bulk_count != 0:
            return self.flow.forward_bulk_size / self.flow.forward_bulk_count
        if direction is PacketDirection.REVERSE and self.flow.backward_bulk_count != 0:
            return self.flow.backward_bulk_size / self.flow.backward_bulk_count
        return 0

    def get_packets_per_bulk(self, direction: PacketDirection) -> float:
        """Calculates number of packets per bulk

        Returns:
            float: number of packets per bulk ratio.

        """
        if direction is PacketDirection.FORWARD and self.flow.forward_bulk_count != 0:
            return self.flow.forward_bulk_packet_count / self.flow.forward_bulk_count
        if direction is PacketDirection.REVERSE and self.flow.backward_bulk_count != 0:
            return self.flow.backward_bulk_packet_count / self.flow.backward_bulk_count
        return 0

    def get_bulk_rate(self, direction: PacketDirection) -> float:
        """Calculates bulk rate

        Returns:
            float: bulk size per seconds.

        """
        if (
            direction is PacketDirection.FORWARD
            and self.flow.forward_bulk_duration != 0
        ):
            return self.flow.forward_bulk_size / self.flow.forward_bulk_duration
        if (
            direction is PacketDirection.REVERSE
            and self.flow.backward_bulk_duration != 0
        ):
            return self.flow.backward_bulk_size / self.flow.backward_bulk_duration
        return 0
