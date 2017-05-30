import struct

from response.base_response import Response
from response.methods import add_name


class TXTResponse(Response):
    def __init__(self, domain_name):
        super().__init__()
        self.domain_name = domain_name

        self.text_length = None
        self.text = None

    def add_specific_info(self, packet, start):
        self.extract_query_info(packet, start)
        start += 10
        self.text_length = struct.unpack("!B", packet[start:start + 1])[0]
        self.text = struct.unpack(
            "!{}B".format(self.text_length),
            packet[start + 1: start + 1 + self.text_length])
        self.part_len = 10 + self.data_len

    def build_packet(self, url, ttl):
        packet = b""
        packet = add_name(packet, url.split("."))
        packet += struct.pack("!H", self.type)
        packet += struct.pack("!H", self.class_)
        packet += struct.pack("!I", ttl)
        packet += struct.pack("!H", self.data_len)
        packet += struct.pack("!B", self.text_length)
        for letter in self.text:
            packet += struct.pack("!B", letter)
        return packet
