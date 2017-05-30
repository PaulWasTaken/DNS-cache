import struct


class Response:
    format = "!HHIH"
    numeric_types = [1, 12, 28]

    def __init__(self):
        self.domain_name = None
        self.type = None
        self.class_ = None
        self.ttl = None
        self.data_len = None
        self.data = None
        self.part_len = 0

    def get_padding_if_variable_len(self, packet, current):
        padding = 0
        try:
            while packet[current] != 192:
                if padding > 64:
                    raise IndexError()
                padding += 1
                current += 1
            padding += 2
            return padding
        except IndexError:
            return len(self.domain_name) + 2

    def extract_query_info(self, packet, start):
        unpacked = struct.unpack(Response.format, packet[start:start + 10])
        self.type = unpacked[0]
        self.class_ = unpacked[1]
        self.ttl = unpacked[2]
        self.data_len = unpacked[3]
        self.data = struct.unpack("!{}B".format(self.data_len),
                                  packet[start + 10:
                                  start + 10 + self.data_len])

    def __repr__(self):
        return "{} {} {} {} {} {}".format(
            self.domain_name, self.type, self.class_, self.ttl,
            self.data_len, self.data)
