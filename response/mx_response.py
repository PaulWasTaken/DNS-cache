import struct

from response.base_response import Response
from response.methods import add_name
from response.response_processor import extract_url


class MXResponse(Response):
    def __init__(self, domain_name):
        super().__init__()
        self.domain_name = domain_name

        self.mail_pref = None

    def add_specific_info(self, packet, start):
        self.extract_query_info(packet, start)
        start += 10
        self.mail_pref = struct.unpack("!H", packet[start:start + 2])[0]
        start += 2
        self.data = extract_url(packet, start)
        self.part_len = 10 + self.data_len
        self.data_len = len(self.data) + 4

    def build_packet(self, ttl):
        packet = b""
        packet = add_name(packet, self.domain_name.split("."))
        packet += struct.pack("!H", self.type)
        packet += struct.pack("!H", self.class_)
        packet += struct.pack("!I", ttl)
        packet += struct.pack("!H", self.data_len)
        packet += struct.pack("!H", self.mail_pref)
        packet = add_name(packet, self.data.split("."))
        return packet
