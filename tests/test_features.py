import time
from typing import Union

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from cicflowmeter.features.context import PacketDirection, get_packet_flow_key
from cicflowmeter.flow import Flow


def create_mock_packet(
    src_ip="192.168.1.2",
    dst_ip="192.168.1.1",
    src_port=12345,
    dst_port=80,
    proto: Union[TCP, UDP, ICMP] = TCP,
    timestamp=None,
):
    """Helper function to create a mock packet with a specific timestamp."""
    if timestamp is None:
        timestamp = time.time()

    ether = Ether()
    ip = IP(src=src_ip, dst=dst_ip)
    transport = proto()
    if proto == TCP or proto == UDP:
        transport.sport = src_port
        transport.dport = dst_port

    packet = ether / ip / transport
    packet.time = timestamp
    return packet


@pytest.fixture
def mock_packets():
    """Provides a list of packets with increasing timestamps."""
    start_time = time.time()
    packets = [
        # Forward packets
        create_mock_packet(
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=80,
            proto=TCP,
            timestamp=start_time,
        ),
        create_mock_packet(
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=80,
            proto=TCP,
            timestamp=start_time + 0.1,
        ),
        # Reverse packets
        create_mock_packet(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=80,
            dst_port=12345,
            proto=TCP,
            timestamp=start_time + 0.2,
        ),
        create_mock_packet(
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=80,
            dst_port=12345,
            proto=TCP,
            timestamp=start_time + 0.3,
        ),
        # ICMP and UDP for key testing
        create_mock_packet(
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            proto=ICMP,
            timestamp=start_time + 0.4,
        ),
        create_mock_packet(
            src_ip="192.168.1.2",
            dst_ip="192.168.1.1",
            src_port=12346,
            dst_port=53,
            proto=UDP,
            timestamp=start_time + 0.5,
        ),
    ]
    return packets


@pytest.fixture
def mock_flow(mock_packets):
    # TODO: get a real flow with cicflowmeter java version and rewrite testcase
    # Use the first TCP packet to initialize the flow
    flow = Flow(mock_packets[0], PacketDirection.FORWARD)

    # Add subsequent packets
    flow.add_packet(mock_packets[1], PacketDirection.FORWARD)
    flow.add_packet(mock_packets[2], PacketDirection.REVERSE)
    flow.add_packet(mock_packets[3], PacketDirection.REVERSE)

    return flow


@pytest.fixture
def mock_flow_data(mock_flow):
    data = mock_flow.get_data()
    return data


def test_features(mock_flow_data):
    expected_keys = [
        "dst_port",
        "protocol",
        "timestamp",
        "flow_duration",
        "tot_fwd_pkts",
        "tot_bwd_pkts",
        "totlen_fwd_pkts",
        "totlen_bwd_pkts",
        "fwd_pkt_len_max",
        "fwd_pkt_len_min",
        "fwd_pkt_len_mean",
        "fwd_pkt_len_std",
        "bwd_pkt_len_max",
        "bwd_pkt_len_min",
        "bwd_pkt_len_mean",
        "bwd_pkt_len_std",
        "flow_byts_s",
        "flow_pkts_s",
        "flow_iat_mean",
        "flow_iat_std",
        "flow_iat_max",
        "flow_iat_min",
        "fwd_iat_tot",
        "fwd_iat_mean",
        "fwd_iat_std",
        "fwd_iat_max",
        "fwd_iat_min",
        "bwd_iat_tot",
        "bwd_iat_mean",
        "bwd_iat_std",
        "bwd_iat_max",
        "bwd_iat_min",
        "fwd_psh_flags",
        "bwd_psh_flags",
        "fwd_urg_flags",
        "bwd_urg_flags",
        "fwd_header_len",
        "bwd_header_len",
        "fwd_pkts_s",
        "bwd_pkts_s",
        "pkt_len_min",
        "pkt_len_max",
        "pkt_len_mean",
        "pkt_len_std",
        "pkt_len_var",
        "fin_flag_cnt",
        "syn_flag_cnt",
        "rst_flag_cnt",
        "psh_flag_cnt",
        "ack_flag_cnt",
        "urg_flag_cnt",
        "cwr_flag_count",
        "ece_flag_cnt",
        "down_up_ratio",
        "pkt_size_avg",
        "fwd_seg_size_avg",
        "bwd_seg_size_avg",
        "fwd_byts_b_avg",
        "fwd_pkts_b_avg",
        "fwd_blk_rate_avg",
        "bwd_byts_b_avg",
        "bwd_pkts_b_avg",
        "bwd_blk_rate_avg",
        "subflow_fwd_pkts",
        "subflow_fwd_byts",
        "subflow_bwd_pkts",
        "subflow_bwd_byts",
        "init_fwd_win_byts",
        "init_bwd_win_byts",
        "fwd_act_data_pkts",
        "fwd_seg_size_min",
        "active_mean",
        "active_std",
        "active_max",
        "active_min",
        "idle_mean",
        "idle_std",
        "idle_max",
        "idle_min",
    ]
    for expected in expected_keys:
        assert expected in mock_flow_data.keys(), f"Expected key '{expected}' not found"


def test_packet_flow_key(mock_packets):
    tcp_fwd_1, tcp_fwd_2, tcp_rev_1, tcp_rev_2, icmp_packet, udp_packet = mock_packets

    # ICMP should raise exception as it's not TCP/UDP
    with pytest.raises(Exception, match="Only TCP protocols are supported."):
        get_packet_flow_key(icmp_packet, PacketDirection.FORWARD)

    """
    get_packet_flow_key returns a tuple:
    Forward: (src_ip, dst_ip, src_port, dst_port)
    Reverse: (dst_ip, src_ip, dst_port, src_port) - Keys are swapped for lookup
    """
    tcp_fwd_1, tcp_fwd_2, tcp_rev_1, tcp_rev_2, icmp_packet, udp_packet = (
        mock_packets  # Use destructured packets
    )

    tcp_forward_key = get_packet_flow_key(tcp_fwd_1, PacketDirection.FORWARD)
    # Use a reverse packet (tcp_rev_1) to test the REVERSE direction logic
    tcp_reverse_key = get_packet_flow_key(tcp_rev_1, PacketDirection.REVERSE)
    udp_forward_key = get_packet_flow_key(udp_packet, PacketDirection.FORWARD)
    # Use the same UDP packet but request REVERSE direction key
    udp_reverse_key = get_packet_flow_key(udp_packet, PacketDirection.REVERSE)

    # Check structure
    assert len(tcp_forward_key) == 4
    assert len(tcp_reverse_key) == 4

    # Test IP/Port values for FORWARD key (using tcp_fwd_1)
    assert tcp_forward_key[0] == "192.168.1.2"
    assert tcp_forward_key[1] == "192.168.1.1"
    assert tcp_forward_key[2] == 12345
    assert tcp_forward_key[3] == 80

    # Test IP/Port values for REVERSE key (using tcp_rev_1)
    # The key should represent the original flow direction (1.2 -> 1.1),
    # even though the packet is 1.1 -> 1.2
    assert tcp_reverse_key[0] == "192.168.1.2"  # Original Src IP
    assert tcp_reverse_key[1] == "192.168.1.1"  # Original Dst IP
    assert tcp_reverse_key[2] == 12345  # Original Src Port
    assert tcp_reverse_key[3] == 80  # Original Dst Port

    # Test consistency between TCP and UDP forward keys (different ports)
    assert tcp_forward_key[0] == udp_forward_key[0]  # src ip
    assert tcp_forward_key[1] == udp_forward_key[1]  # dst ip
    assert tcp_forward_key[2] != udp_forward_key[2]  # src port (12345 vs 12346)
    assert tcp_forward_key[3] != udp_forward_key[3]  # dst port (80 vs 53)

    # Test consistency between forward and reverse keys for the *same* protocol flow
    assert tcp_forward_key[0] == tcp_reverse_key[0]  # Effective Src IP
    assert tcp_forward_key[1] == tcp_reverse_key[1]  # Effective Dst IP
    assert tcp_forward_key[2] == tcp_reverse_key[2]  # Effective Src Port
    assert tcp_forward_key[3] == tcp_reverse_key[3]  # Effective Dst Port


def test_flow_duration(mock_flow_data):
    # Duration should be roughly 0.3 seconds based on mock_packets timestamps
    # (last packet time - first packet time)
    assert isinstance(mock_flow_data["flow_duration"], float)
    assert mock_flow_data["flow_duration"] > 0.0
    # Allow for slight timing variations during test execution
    assert 0.29 < mock_flow_data["flow_duration"] < 0.31


def test_flow_packet_count(mock_flow_data):
    assert mock_flow_data["tot_fwd_pkts"] == 2
    assert mock_flow_data["tot_bwd_pkts"] == 2


def test_flow_packet_rate(mock_flow_data):
    # With non-zero duration, rates should be calculable and non-negative
    assert isinstance(mock_flow_data["flow_pkts_s"], float)
    assert isinstance(mock_flow_data["flow_byts_s"], float)
    assert isinstance(mock_flow_data["fwd_pkts_s"], float)
    assert isinstance(mock_flow_data["bwd_pkts_s"], float)

    assert mock_flow_data["flow_pkts_s"] >= 0
    assert mock_flow_data["flow_byts_s"] >= 0
    assert mock_flow_data["fwd_pkts_s"] >= 0
    assert mock_flow_data["bwd_pkts_s"] >= 0

    # Check if rates are roughly correct (4 packets / ~0.3s = ~13.3 pkts/s)
    # Allow for some imprecision
    assert 13.0 < mock_flow_data["flow_pkts_s"] < 13.5


def test_flow_protocol(mock_flow_data):
    assert mock_flow_data["protocol"] in (17, 6)
