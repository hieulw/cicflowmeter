from enum import Enum, auto

from scapy.packet import Packet


class PacketDirection(Enum):
    """Packet Direction creates constants for the direction of the packets.

    There are two given directions that the packets can Feature along
    the line. PacketDirection is an enumeration with the values
    forward (1) and reverse (2).
    """

    FORWARD = auto()
    REVERSE = auto()


def get_packet_flow_key(packet: Packet, direction: PacketDirection) -> tuple:
    """Creates a key signature for a packet.

    Summary:
        Creates a key signature for a packet so it can be
        assigned to a flow.

    Args:
        packet: A network packet
        direction: The direction of a packet

    Returns:
        A tuple of the String IPv4 addresses of the destination,
        the source port as an int,
        the time to live value,
        the window size, and
        TCP flags.

    """

    if "TCP" in packet:
        protocol = "TCP"
    elif "UDP" in packet:
        protocol = "UDP"
    else:
        raise Exception("Only TCP protocols are supported.")

    if direction == PacketDirection.FORWARD:
        dest_ip = packet["IP"].dst
        src_ip = packet["IP"].src
        src_port = packet[protocol].sport
        dest_port = packet[protocol].dport
    else:
        dest_ip = packet["IP"].src
        src_ip = packet["IP"].dst
        src_port = packet[protocol].dport
        dest_port = packet[protocol].sport

    return dest_ip, src_ip, src_port, dest_port
