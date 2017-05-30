import struct
from collections import namedtuple

from response.methods import add_name
from response.response_processor import extract_url

AdditionalQueryInfo = namedtuple("AdditionalQueryInfo",
                                 "exists, start, amount")


def dismantle_query(data, additional):
    url = extract_url(data)
    type_ = struct.unpack("!H", data[len(url) + 2:len(url) + 4])[0]
    additional_info = AdditionalQueryInfo(False, 0, 0)
    if additional:
        additional_info = AdditionalQueryInfo(True, len(url) + 18, additional)
    return Query(url, type_), additional_info


class Query:
    def __init__(self, url, type_, sub_url=None):
        self.url = url
        self.type_ = type_
        self.sub_url = sub_url


def build_query(url, type_=1):
    packet = struct.pack("!H", 65535)
    # packet += struct.pack("!H", 33024)
    packet += struct.pack("!H", 288)
    packet += struct.pack("!H", 1)
    packet += struct.pack("!H", 0)
    packet += struct.pack("!H", 0)
    packet += struct.pack("!H", 0)
    packet = add_name(packet, url.split("."))
    packet += struct.pack("!H", type_)
    packet += struct.pack("!H", 1)
    return packet
