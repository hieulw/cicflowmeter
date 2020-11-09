import json
import os

from scapy.layers.tls.record import TLSApplicationData

import constants
from features.context.packet_direction import PacketDirection


class Clump:
    """Represents several packets with the same direction with short time between them"""

    def __init__(self, direction):
        self.direction = direction
        self.packets = 0
        self.size = 0
        self.latest_timestamp = 0
        self.first_timestamp = 0

    def add_packet(self, packet):
        if self.first_timestamp == 0:
            self.first_timestamp = packet.time
        self.packets += 1
        self.size += len(packet[TLSApplicationData])
        self.latest_timestamp = packet.time

    def accepts(self, packet, direction):
        if direction != self.direction:
            return False
        if (
            self.latest_timestamp != 0
            and packet.time - self.latest_timestamp > constants.CLUMP_TIMEOUT
        ):
            return False
        return True

    def duration(self):
        return self.latest_timestamp - self.first_timestamp


class FlowClumpsContainer:
    """Represents a sequence of clumps in a Flow"""

    def __init__(self, flow, clumps):
        self.flow = flow
        self.clumps = clumps

    def output(self):
        results = []

        latest_clump_end_timestamp = None

        count = 0
        for c in self.clumps:
            if latest_clump_end_timestamp is None:
                latest_clump_end_timestamp = c.first_timestamp
            count += 1
            results.append(
                [
                    float(
                        c.first_timestamp - latest_clump_end_timestamp
                    ),  # inter-arrival duration
                    float(c.duration()),
                    c.size,
                    c.packets,
                    1 if c.direction == PacketDirection.FORWARD else -1,
                ]
            )
            latest_clump_end_timestamp = c.latest_timestamp

        return results, count

    def to_json_file(self, directory):
        preferred_name = "{}_{}-{}_{}.json".format(
            self.flow.src_ip, self.flow.src_port, self.flow.dest_ip, self.flow.dest_port
        )
        file_path = os.path.join(directory, preferred_name)

        output, count = self.output()

        if count < 5:
            return

        if os.path.exists(file_path):
            f = open(file_path, "r")
            contents = json.load(f)
            contents.append(output)
            f.close()
        else:
            contents = [output]

        f = open(file_path, "w")

        json.dump(contents, f, indent=2)
        f.close()
