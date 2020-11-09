from scapy.layers.tls.record import TLS, TLSApplicationData

from .flow_clumps import Clump, FlowClumpsContainer


class Processor:
    def __init__(self, flow):
        self.flow = flow

        self._segment_size = 20

    def _clumps(self):
        current_clump = None

        for packet, direction in self.flow.packets:
            if TLS not in packet:
                continue

            if TLSApplicationData not in packet:
                continue

            if len(packet[TLSApplicationData]) < 40:
                # PING frame (len = 34) or other useless frames
                continue

            if current_clump is None:
                current_clump = Clump(direction=direction)

            if not current_clump.accepts(packet, direction):
                yield current_clump
                current_clump = Clump(direction=direction)

            current_clump.add_packet(packet)

        if current_clump is not None:
            yield current_clump

    def create_flow_clumps_container(self):
        return FlowClumpsContainer(flow=self.flow, clumps=self._clumps())
