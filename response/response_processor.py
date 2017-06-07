import struct

from response.address_response import AddressResponse
from response.any_response import ANYResponse
from response.base_response import Response
from response.cname_response import CNAMEResponse
from response.methods import extract_url
from response.mx_response import MXResponse
from response.ns_response import NSResponse
from response.ptr_response import PTRResponse
from response.soa_response import SOAResponse
from response.txt_response import TXTResponse


def dismantle_response(packet, query_len):
    data = []
    current_position = query_len
    while current_position != len(packet):
        info = dismantle(packet, current_position)
        current_position += info.part_len
        data.append(info)
    return data


def dismantle(packet, current_pos):
    response = Response()
    indicator = struct.unpack("!B", packet[current_pos:current_pos + 1])[0]
    if indicator == 192:
        start = struct.unpack(
            "!B", packet[current_pos + 1:current_pos + 2])[0]
        response.domain_name = extract_url(packet, start)
        padding = 2
    else:
        response.domain_name = extract_url(packet, current_pos)
        padding = response.get_padding_if_variable_len(packet, current_pos)

    start = current_pos + padding

    type_ = struct.unpack("!H", packet[start:start + 2])[0]

    if type_ in [1, 28]:
        response = AddressResponse(response.domain_name)
    elif type_ == 2:
        response = NSResponse(response.domain_name)
    elif type_ == 5:
        response = CNAMEResponse(response.domain_name)
    elif type_ == 6:
        response = SOAResponse(response.domain_name)
    elif type_ == 12:
        response = PTRResponse(response.domain_name)
    elif type_ == 15:
        response = MXResponse(response.domain_name)
    elif type_ == 16:
        response = TXTResponse(response.domain_name)
    elif type_ == 255:
        response = ANYResponse(response.domain_name)
    else:
        raise NotImplementedError(type_)

    response.add_specific_info(packet, start)
    response.part_len += padding

    return response
