from scapy.packet import Packet
from scapy.sessions import DefaultSession

from cicflowmeter.writer import output_writer_factory

from .constants import EXPIRED_UPDATE, GARBAGE_COLLECT_PACKETS
from .features.context import PacketDirection, get_packet_flow_key
from .flow import Flow
from .utils import get_logger


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.logger = get_logger(self.verbose)
        self.packets_count = 0
        self.output_writer = output_writer_factory(self.output_mode, self.output_file)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        del self.output_writer
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet: Packet):
        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != "csv":
            if "TCP" not in packet:
                return
            elif "UDP" not in packet:
                return

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            self.flows[(packet_flow_key, count)] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break
        elif "F" in packet.flags:
            # If it has FIN flag then early collect flow and continue
            flow.add_packet(packet, direction)
            self.garbage_collect(packet.time)
            return

        flow.add_packet(packet, direction)

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or flow.duration > 120:
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        self.logger.debug(f"Garbage Collection Began. Flows = {len(self.flows)}")
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)

            if (
                latest_time is not None
                and latest_time - flow.latest_timestamp < EXPIRED_UPDATE
                and flow.duration < 90
            ):
                continue

            self.output_writer.write(flow.get_data())
            del self.flows[k]
        self.logger.debug(f"Garbage Collection Finished. Flows = {len(self.flows)}")


def generate_session_class(output_mode, output_file, verbose):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "output_mode": output_mode,
            "output_file": output_file,
            "verbose": verbose,
        },
    )
