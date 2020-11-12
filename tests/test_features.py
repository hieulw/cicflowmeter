from scapy.all import IP, TCP, UDP, ICMP, Ether
from cicflowmeter.features.context.packet_flow_key import get_packet_flow_key
from cicflowmeter.features.context.packet_direction import PacketDirection
from cicflowmeter.flow import Flow
import pytest


@pytest.fixture
def mock_packet():
    icmp_packet = IP(src="192.168.1.2", dst="192.168.1.1") / ICMP()
    tcp_packet = IP(src="192.168.1.2", dst="192.168.1.1", ihl=5) / TCP(dport=80)
    udp_packet = IP(src="192.168.1.2", dst="192.168.1.1", ihl=5) / UDP(dport=53)
    return icmp_packet, tcp_packet, udp_packet


@pytest.fixture
def mock_flow(mock_packet):
    # TODO: get a real flow with cicflowmeter java version and rewrite testcase
    _, tcp_packet, udp_packet = mock_packet
    flow = Flow(tcp_packet, PacketDirection.FORWARD)

    flow.add_packet(tcp_packet, PacketDirection.FORWARD)
    flow.add_packet(tcp_packet, PacketDirection.REVERSE)
    flow.add_packet(tcp_packet, PacketDirection.FORWARD)
    flow.add_packet(tcp_packet, PacketDirection.REVERSE)

    return flow


@pytest.fixture
def mock_flow_data(mock_flow):
    data = mock_flow.get_data()
    return data


def test_flow_data(mock_flow_data):
    print(mock_flow_data)
    assert len(mock_flow_data) > 70


def test_packet_flow_key(mock_packet):
    icmp_packet, tcp_packet, udp_packet = mock_packet

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


def test_flow_duration(mock_flow_data):
    assert float(mock_flow_data["flow_duration"]).is_integer()


def test_flow_packet_count(mock_flow_data):
    assert mock_flow_data["tot_fwd_pkts"] == 2
    assert mock_flow_data["tot_bwd_pkts"] == 2


def test_flow_packet_rate(mock_flow_data):
    assert mock_flow_data["flow_pkts_s"] == 0
    assert mock_flow_data["flow_byts_s"] == 0
    assert mock_flow_data["fwd_pkts_s"] == 0
    assert mock_flow_data["bwd_pkts_s"] == 0


def test_flow_protocol(mock_flow_data):
    assert mock_flow_data["protocol"] in (17, 6)
