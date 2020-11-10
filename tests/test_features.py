from scapy.all import IP, TCP, UDP, ICMP
from cicflowmeter.features.context.packet_flow_key import get_packet_flow_key
from cicflowmeter.features.context.packet_direction import PacketDirection
import pytest


def test_packet_flow_key():
    icmp_packet = IP(src="192.168.1.2", dst="192.168.1.1") / ICMP()
    tcp_packet = IP(src="192.168.1.2", dst="192.168.1.1") / TCP()
    udp_packet = IP(src="192.168.1.2", dst="192.168.1.1") / UDP()

    with pytest.raises(Exception):
        get_packet_flow_key(icmp_packet, PacketDirection.FORWARD)

    """
    get_packet_flow_key return a tuple (dest_ip, src_ip, src_port, dest_port)
    """
    tcp_forward = get_packet_flow_key(tcp_packet, PacketDirection.FORWARD)
    tcp_backward = get_packet_flow_key(tcp_packet, PacketDirection.REVERSE)
    udp_forward = get_packet_flow_key(udp_packet, PacketDirection.FORWARD)
    udp_backward = get_packet_flow_key(udp_packet, PacketDirection.REVERSE)

    # Test IP match source and destination
    assert tcp_forward[0] == udp_forward[0]
    assert tcp_forward[0] == tcp_backward[1]
    # Test Port match source and destination
    assert udp_forward[2] == udp_backward[3]
    assert tcp_forward[2] == tcp_backward[3]
