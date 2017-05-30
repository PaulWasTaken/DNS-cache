import struct


def insert_answers_amount(ans, auth, add, response):
    ans = struct.pack("!H", ans)
    auth = struct.pack("!H", auth)
    add = struct.pack("!H", add)
    response = response[:6] + ans + auth + add + response[12:]
    return response


def extract_records(records, cname, type_):
    result = b""
    amount = 0
    for record in records:
        if type_ != record.data.type:
            continue
        info = record.data
        amount += 1
        result += info.build_response(
            cname, info.type, info.class_,
            record.ttl, info.data_len, info.data)
    return amount, result


def form_response(cache, cname, type_, keys, sub_url=None):
    response = b""
    amounts = []
    for record_name in keys:
        counter = 0
        for record in cache[record_name]:
            if sub_url:
                if record.data.domain_name != sub_url:
                    continue
            if type_ != record.data.type:
                continue
            info = record.data
            counter += 1
            response += info.build_packet(cname, record.ttl)
        amounts.append(counter)

    return response, amounts


def add_query_info(response, source, add_info):
    if add_info.exists:  # 32896 - response, recursion
        response = source[:2] + struct.pack("!H", 32896) + \
                   source[4:add_info.start] + response
        response += source[add_info.start:]
    else:
        response = source[:2] + struct.pack("!H", 32896) + \
                   source[4:] + response

    return response


def process_query(query):
    parts = query.url.split(".")
    if len(parts) == 3:
        query.sub_url = ".".join(parts[1:])
    if len(parts) > 3:
        raise NotImplementedError
