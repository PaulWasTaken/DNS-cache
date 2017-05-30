import struct

from response.base_response import Response
from response.methods import add_name, extract_url


class CNAMEResponse(Response):
    def __init__(self, domain_name):
        super().__init__()
        self.domain_name = domain_name

    def add_specific_info(self, packet, start):
        try:
            self.extract_query_info(packet, start)
            self.data = extract_url(packet, start + 10)
            self.part_len = 10 + self.data_len
            self.data_len = len(self.data) + 2
        except struct.error:
            unpacked = struct.unpack(Response.format, packet[start:start + 4])
            self.type = unpacked[0]
            self.class_ = unpacked[1]
            self.part_len = len(self.domain_name) + 4

    def build_packet(self, url, ttl):
        packet = b""
        packet = add_name(packet, url.split("."))

        packet += struct.pack("!H", self.type)
        packet += struct.pack("!H", self.class_)

        return packet
