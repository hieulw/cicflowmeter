class FlagCount:
    """This class extracts features related to the Flags Count.

    TCP Flags: (UDP does not have flag)
        SYN: Synchronization
        ACK: Acknowledgement
        FIN: Finish
        RST: Reset
        URG: Urgent
        PSH: Push
        CWR
        ECE
    """

    def __init__(self, flow):
        self.flow = flow

    def count(self, flag, packet_direction=None) -> bool:
        """Count packets by direction.

        Returns:
            packets_count (int):

        """
        count = 0
        if packet_direction is not None:
            packets = (
                packet
                for packet, direction in self.flow.packets
                if direction == packet_direction
            )
        else:
            packets = (packet for packet, _ in self.flow.packets)

        for packet in packets:
            if flag[0] in packet.sprintf("%TCP.flags%"):
                count += 1
        return count
