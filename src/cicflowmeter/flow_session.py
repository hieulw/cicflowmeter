import threading
from scapy.packet import Packet
from scapy.sessions import DefaultSession

from cicflowmeter.writer import output_writer_factory

from .constants import EXPIRED_UPDATE, PACKETS_PER_GC
from .features.context import PacketDirection, get_packet_flow_key
from .flow import Flow
from .utils import get_logger


class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(
        self, output_mode=None, output=None, fields=None, verbose=False, *args, **kwargs
    ):
        self.flows: dict[tuple, Flow] = {}
        self.verbose = verbose
        self.fields = fields
        self.output_mode = output_mode
        self.output = output
        self.logger = get_logger(self.verbose)
        self.packets_count = 0
        self.output_writer = output_writer_factory(self.output_mode, self.output)

        # NEW: lock protecting self.flows
        self._lock = threading.Lock()

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        # Use the lock to avoid races with background GC (if any)
        with self._lock:
            self.garbage_collect(None)
            # delete writer after flush
            try:
                del self.output_writer
            except Exception:
                pass
        return super(FlowSession, self).toPacketList()

    def process(self, pkt: Packet):
        """
        Needed for use in scapy versions above 2.5 because of a breaking change in scapy.
        Functionality is same as on_packet_received, but returnvalues are added.
        """
        self.logger.debug(f"Packet {self.packets_count}: {pkt}")
        count = 0
        direction = PacketDirection.FORWARD

        if "TCP" not in pkt and "UDP" not in pkt:
            return None  # Do not return the packet, prevents Scapy from printing

        try:
            packet_flow_key = get_packet_flow_key(pkt, direction)
            # Acquire lock only while accessing self.flows
            with self._lock:
                flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return None

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(pkt, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # Create a new flow (we need to insert into dict under lock)
            direction = PacketDirection.FORWARD
            flow = Flow(pkt, direction)
            packet_flow_key = get_packet_flow_key(pkt, direction)
            with self._lock:
                self.flows[(packet_flow_key, count)] = flow

        elif (pkt.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (pkt.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                with self._lock:
                    flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(pkt, direction)
                    with self._lock:
                        self.flows[(packet_flow_key, count)] = flow
                    break
        elif "F" in pkt.flags:
            # FIN: add packet and early collect
            flow.add_packet(pkt, direction)
            # call garbage_collect with current time; protect with lock inside GC
            self.garbage_collect(pkt.time)
            return None

        flow.add_packet(pkt, direction)

        # call garbage_collect only occasionally; the background GC thread will cover periodic execution
        if self.packets_count % PACKETS_PER_GC == 0 or flow.duration > 120:
            self.garbage_collect(pkt.time)

        return None

    def get_flows(self):
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        # Acquire lock while we iterate and delete flows
        with self._lock:
            keys = list(self.flows.keys())
        for k in keys:
            # get flow without holding lock to minimize lock hold time
            with self._lock:
                flow = self.flows.get(k)
            if not flow or (
                latest_time is not None
                and latest_time - flow.latest_timestamp < EXPIRED_UPDATE
                and flow.duration < 90
            ):
                continue

            # Write the flow out - writer may perform IO (do it outside the lock)
            data = flow.get_data(self.fields)

            # Now safely delete the entry under lock
            with self._lock:
                # re-check existence
                if k in self.flows:
                    del self.flows[k]

            # Finally write to output (IO outside the lock)
            self.output_writer.write(data)
            self.logger.debug(f"Flow Collected! Remain Flows = {len(self.flows)}")

    def flush_flows(self):
        # Write all remaining flows to output (for end of sniffing)
        with self._lock:
            items = list(self.flows.values())
            self.flows.clear()
        for flow in items:
            self.output_writer.write(flow.get_data(self.fields))
        try:
            del self.output_writer
        except Exception:
            pass
