import logging
import socket
import time
import struct

from concurrent.futures import ThreadPoolExecutor

from cache import DNSServerCache
from packet_processor import insert_answers_amount, add_query_info, \
    process_query
from query import dismantle_query, build_query
from response.response_processor import dismantle_response


def print_result(address, query, source):
    print("{ip}, {type}, {url}, {source}"
          .format(ip=address,
                  type=DNSServer.query_types[query.type_],
                  url=query.url,
                  source=source))


class DNSServer:
    query_types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA"
    }

    def __init__(self, settings, debug=False):
        server, port = settings.server_info.split(":")
        self.forwarder_port = int(port) if port else 53
        self.upper_server = server if server else "8.8.8.8"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.1)
        self.port = settings.port
        self.sock.bind(("localhost", self.port))
        self.logging(debug)
        self.cache = DNSServerCache()

    @staticmethod
    def logging(debug):
        if debug:
            logging.basicConfig(
                format=u'[%(asctime)s]  %(message)s', level=logging.DEBUG,
                filename=u'log.log')
            logging.debug("\n---------The application was started---------\n")

    def invoke(self):
        print("Was started at {port} port. Time: {data} GMT+0".format(
            port=self.port, data=time.asctime(time.gmtime())))
        counter = 0
        with ThreadPoolExecutor(max_workers=64) as executor:
            try:
                while 1:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        # print("Connected: {}:{}".format(addr[0], addr[1]))
                        logging.debug("Received from a client: {}\n"
                                      .format(data))
                    except socket.timeout:
                        counter += 1
                        if counter == 10:
                            self.cache.update_ttl()
                            counter = 0
                        continue
                    executor.submit(self.process_new_client,
                                    addr, data).result()
            except KeyboardInterrupt:
                print("Finishing...")
                logging.debug("\n---------The program was closed.---------\n")
                self.sock.close()
                executor.shutdown()

    def process_new_client(self, addr, data):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            id_ = data[:2]
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("", self.port))
                sock.settimeout(2)
                # ans = struct.unpack("!H", data[])
                # auth = struct.unpack("!H", data[])
                add = struct.unpack("!H", data[10:12])[0]
                query, add_info = dismantle_query(data[12:], add)
                process_query(query)
                if self.cache.check(query):
                    self.data_in_cache(query, sock, addr, data, add_info)
                    print_result(addr[0], query, "cache")
                else:
                    self.data_not_in_cache(id_, query, sock, addr)
                    print_result(addr[0], query, "forwarder")
            except socket.timeout:
                print("The upper server hasn't answered.\n"
                      "Query id: {}".format(struct.unpack("!H", id_)[0]))
            except struct.error:
                print("Probably incorrect server response. Try another one.\n"
                      "Query id: {}".format(struct.unpack("!H", id_)[0]))

    def data_in_cache(self, query, sock, addr, data, add_info):
        packet = self.form_response(data, query, add_info)
        sock.sendto(packet, addr)
        logging.debug("Send to a client: {}\n".format(packet))

    def data_not_in_cache(self, id_, query, sock, addr):
        packet = build_query(query.url, query.type_)
        logging.debug("Send to a DNS server: {}\n".format(packet))
        sock.sendto(packet, (self.upper_server, self.forwarder_port))

        data, _ = sock.recvfrom(4096)
        logging.debug("Received from a DNS server: {}\n".format(data))
        self.cache.add(query.url, data[6:12],
                       dismantle_response(data, len(packet)))
        data = id_ + data[2:]
        sock.sendto(data, addr)
        logging.debug("Send to a client: {}\n".format(data))

    def form_response(self, source, query, add_info):
        response, [answer_amount, authority_amount, additional_amount] = \
            self.cache.get_url_data(query.url, query.type_, query.sub_url)

        response = add_query_info(response, source, add_info)

        response = insert_answers_amount(
            answer_amount, authority_amount,
            additional_amount + add_info.amount, response)

        return response
