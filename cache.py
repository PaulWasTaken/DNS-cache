import struct

from packet_processor import form_response
from query.query_types import QueryTypes

ANSWER_RECORDS = "answer"
AUTHORITY_RECORDS = "authority"
ADDITIONAL_RECORDS = "additional"


class Record:
    def __init__(self, data, ttl):
        self.data = data
        self.ttl = ttl

    def __hash__(self):
        return hash((self.data.class_, self.data.type, self.data.data))

    def __eq__(self, other):
        return self.data == other.data


class DNSServerCache:
    def __init__(self):
        self.cache = {}

    def check(self, query):
        if query.type_ == QueryTypes.ANY.value:
            return True
        if not query.sub_url:
            return self._search_in_cache(query.url, query.type_)
        else:
            if self._search_in_cache(query.url, query.type_):
                return True
            return self._search_in_cache(query.sub_url, query.type_, query.url)

    def _search_in_cache(self, url, type_, sub_url=None):
        if url in self.cache:
            for records_name in self.cache[url]:
                for record in self.cache[url][records_name]:
                    if sub_url:
                        if record.data.type is type_ and \
                                        record.data.domain_name == sub_url:
                            return True
                    else:
                        if record.data.type is type_:
                            return True

    def add(self, url, counters, data):
        answer_amount = struct.unpack("!H", counters[:2])[0]
        authority_amount = struct.unpack("!H", counters[2:4])[0]
        additional_amount = struct.unpack("!H", counters[4:])[0]

        record_names = [ANSWER_RECORDS, AUTHORITY_RECORDS, ADDITIONAL_RECORDS]
        amounts = [answer_amount, authority_amount, additional_amount]

        if url not in self.cache:
            self.cache[url] = {ANSWER_RECORDS: [],
                               AUTHORITY_RECORDS: [],
                               ADDITIONAL_RECORDS: []}

        start = end = 0
        for record_name, amount in list(zip(record_names, amounts)):
            end += amount
            self.cache[url][record_name] += [Record(info, info.ttl)
                                             for info in data[start:end]]
            self.cache[url][record_name] = list(
                set(self.cache[url][record_name]))
            start += amount

    def update_ttl(self):
        to_delete = {}
        for url in self.cache:
            for record_type in self.cache[url]:
                for info in self.cache[url][record_type]:
                    info.ttl -= 1
                    if info.ttl == 0:
                        if url not in to_delete:
                            to_delete[url] = []
                        to_delete[url].append((record_type, info))
        for url, records in to_delete.items():
            for record in records:
                self.cache[url][record[0]].remove(record[1])

    def get_cname(self, url):
        for records_name in self.cache[url]:
            for record in self.cache[url][records_name]:
                if record.data.type == QueryTypes.CNAME.value:
                    return record.data.data
        return url

    def get_url_data(self, url, type_, sub_url):
        if url in self.cache:
            cname = self.get_cname(url)
            selector = make_selector(type_, cname is not url)
            return form_response(self.cache[url], selector,
                                 [ANSWER_RECORDS, AUTHORITY_RECORDS,
                                  ADDITIONAL_RECORDS])
        elif sub_url in self.cache:
            cname = self.get_cname(sub_url)
            selector = make_selector(type_, cname is not url, sub_url)
            return form_response(self.cache[sub_url], selector,
                                 [ANSWER_RECORDS, AUTHORITY_RECORDS,
                                  ADDITIONAL_RECORDS])
        else:
            raise KeyError


def make_selector(type_, add_cname, sub_url=None):
    def selector(record):
        if type_ != QueryTypes.ANY.value:  # Any
            if sub_url:
                if record.data.domain_name == sub_url:
                    return True
            if add_cname:
                if record.data.type == QueryTypes.CNAME.value:
                    return True
            if type_ is record.data.type:
                return True
            return False
        return True

    return selector
