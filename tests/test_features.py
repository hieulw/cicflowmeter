from scapy.all import IP, TCP, UDP, ICMP
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
        "cwe_flag_count",
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
        assert expected in mock_flow_data.keys()


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
