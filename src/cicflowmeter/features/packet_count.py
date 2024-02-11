from .context import PacketDirection
from .packet_time import PacketTime


class PacketCount:
    """This class extracts features related to the Packet Count."""

    def __init__(self, flow):
        self.flow = flow

    def get_total(self, packet_direction=None) -> int:
        """Count packets by direction.

        Returns:
            packets_count (int):

        """
        if packet_direction is not None:
            return len(
                [
                    packet
                    for packet, direction in self.flow.packets
                    if direction == packet_direction
                ]
            )
        return len(self.flow.packets)

    def get_rate(self, packet_direction=None) -> float:
        """Calculates the rate of the packets being transfered
        in the current flow.

        Returns:
            float: The packets/sec.

        """
        duration = PacketTime(self.flow).get_duration()

        if duration == 0:
            rate = 0
        else:
            rate = self.get_total(packet_direction) / duration

        return rate

    def get_down_up_ratio(self) -> float:
        """Calculates download and upload ratio.

        Returns:
            float: down/up ratio
        """
        forward_size = self.get_total(PacketDirection.FORWARD)
        backward_size = self.get_total(PacketDirection.REVERSE)
        if forward_size > 0:
            return backward_size / forward_size
        return 0

    @staticmethod
    def get_payload(packet):
        if "TCP" in packet:
            return packet["TCP"].payload
        elif "UDP" in packet:
            return packet["UDP"].payload
        return 0

    def has_payload(self, packet_direction=None) -> int:
        """Count packet has payload.

        Returns:
            int: packets
        """

        if packet_direction is not None:
            return len(
                [
                    packet
                    for packet, direction in self.flow.packets
                    if direction == packet_direction
                    and len(self.get_payload(packet)) > 0
                ]
            )
        return len(
            [
                packet
                for packet, _ in self.flow.packets
                if len(self.get_payload(packet)) > 0
            ]
        )
