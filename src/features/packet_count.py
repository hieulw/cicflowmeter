from .packet_time import PacketTime
from .context.packet_direction import PacketDirection


class PacketCount:
    """This class extracts features related to the Packet Count."""

    def __init__(self, feature):
        self.feature = feature

    def get_total(self, packet_direction=None) -> int:
        """Count packets by direction.

        Returns:
            packets_count (int):

        """

        if packet_direction is not None:
            return len(
                [
                    packet
                    for packet, direction in self.feature.packets
                    if direction == packet_direction
                ]
            )
        return len(self.feature.packets)

    def get_rate(self, packet_direction=None) -> float:
        """Calculates the rate of the packets being transfered
        in the current flow.

        Returns:
            float: The packets/sec.

        """
        duration = PacketTime(self.feature).get_duration()

        if duration == 0:
            rate = 0
        else:
            rate = self.get_total(packet_direction) / duration

        return rate

    def get_down_up_ratio(self):
        """Calculates download and upload ratio.

        Returns:
            int: down/up ratio
        """
        forward_size = self.get_total(PacketDirection.FORWARD)
        backward_size = self.get_total(PacketDirection.REVERSE)
        if forward_size > 0:
            return backward_size / forward_size
        return 0
