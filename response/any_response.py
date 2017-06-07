import struct

from response.base_response import Response


class ANYResponse(Response):
    def __init__(self, domain_name):
        super().__init__()
        self.domain_name = domain_name

    def add_specific_info(self, packet, start):
        unpacked = struct.unpack(Response.format, packet[start:start + 4])
        self.type = unpacked[0]
        self.class_ = unpacked[1]
        self.part_len = len(self.domain_name) + 4
