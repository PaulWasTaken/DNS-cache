import struct


def extract_url(data, current_pos=0):
    parts = []
    pointer = current_pos
    while True:
        length = data[pointer]
        if length == 0:
            break
        if length == 192:
            pointer = data[pointer + 1]
            parts.append(extract_url(data, pointer))
            break
        parts.append(data[pointer + 1:pointer + length + 1].decode())
        pointer += length + 1
    return ".".join(parts)


def add_name(packet, split_url):
    for part in split_url:
        packet += struct.pack("!B", len(part))
        for byte in part:
            packet += struct.pack("!c", byte.encode())
    packet += struct.pack("!B", 0)
    return packet


def get_padding(packet, start):
    padding = 0
    while 1:
        if packet[start + padding] == 192:
            padding += 2
            break
        if packet[start + padding] == 0:
            break
        padding += 1
    return padding
