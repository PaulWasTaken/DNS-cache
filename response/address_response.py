import struct

from response.base_response import Response
from response.methods import add_name


class AddressResponse(Response):
    def __init__(self, domain_name):
        super().__init__()
        self.domain_name = domain_name

    def add_specific_info(self, packet, start):
        self.extract_query_info(packet, start)
        self.part_len = 10 + self.data_len

    def build_packet(self, url, ttl):
        packet = b""
        packet = add_name(packet, url.split("."))
        packet += struct.pack("!H", self.type)
        packet += struct.pack("!H", self.class_)
        packet += struct.pack("!I", ttl)
        packet += struct.pack("!H", self.data_len)
        for part in self.data:
            packet += struct.pack("!B", part)
        return packet
