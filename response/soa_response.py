import struct

from response.base_response import Response
from response.methods import get_padding, add_name
from response.response_processor import extract_url


class SOAResponse(Response):
    def __init__(self, domain_name):
        super().__init__()
        self.domain_name = domain_name
        self.primary_ns = None
        self.mailbox = None
        self.serial = None
        self.refresh_interval = None
        self.retry_interval = None
        self.expire_interval = None
        self.min_ttl = None

    def add_specific_info(self, packet, start):
        self.extract_query_info(packet, start)
        start += 10
        self.part_len = 10 + self.data_len
        self.primary_ns = extract_url(packet, start)
        self.data_len = len(self.primary_ns) + 2
        start += get_padding(packet, start)

        self.mailbox = extract_url(packet, start)
        self.data_len += len(self.mailbox) + 2
        start += get_padding(packet, start)

        other_data = struct.unpack("!5I", packet[start:])
        self.serial = other_data[0]
        self.refresh_interval = other_data[1]
        self.retry_interval = other_data[2]
        self.expire_interval = other_data[3]
        self.min_ttl = other_data[4]
        self.data_len += 20

    def build_packet(self, url, ttl):
        packet = b""
        packet = add_name(packet, url.split("."))

        packet += struct.pack("!H", self.type)
        packet += struct.pack("!H", self.class_)
        packet += struct.pack("!I", ttl)
        packet += struct.pack("!H", self.data_len)

        packet = add_name(packet, self.primary_ns.split("."))
        packet = add_name(packet, self.mailbox.split("."))

        packet += struct.pack("!I", self.serial)
        packet += struct.pack("!I", self.refresh_interval)
        packet += struct.pack("!I", self.retry_interval)
        packet += struct.pack("!I", self.expire_interval)
        packet += struct.pack("!I", self.min_ttl)

        return packet
