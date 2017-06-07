import logging
import socket
import struct
import time

from asyncio import as_completed
from cache import DNSServerCache
from concurrent.futures import ThreadPoolExecutor
from cycle_processor import CycleProcessor, CycleError
from error_handler import error_handler
from packet_processor import insert_answers_amount, add_query_info, \
    process_query
from query.query import dismantle_query, build_query
from query.query_types import QueryTypes
from response.response_processor import dismantle_response
from ttl_timer import TTLTimer


def print_result(address, query, source):
    print("{ip}, {type}, {url}, {source}"
          .format(ip=address,
                  type=QueryTypes(query.type_).name,
                  url=query.url,
                  source=source))


class DNSServer:
    def __init__(self, settings, debug=False):
        server_port = settings.server_info.split(":")
        self.forwarder_port = int(server_port[1]) if len(server_port) > 1 \
            else 53
        self.upper_server = server_port[0] if server_port[0] else "8.8.8.8"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.port = settings.port
        self.sock.setblocking(0.1)
        self.sock.bind(("localhost", self.port))
        self.logging(debug)
        self.cache = DNSServerCache()
        self.cycle_processor = CycleProcessor()
        self.ttl_timer = None

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
        with ThreadPoolExecutor(max_workers=64) as executor:
            try:
                self.ttl_timer = TTLTimer(self.cache.update_ttl)
                self.ttl_timer.start()
                while 1:
                    try:
                        data, addr = self.sock.recvfrom(4096)
                        # print("Connected: {}:{}".format(addr[0], addr[1]))
                        logging.debug("Received from a client: {}\n"
                                      .format(data))
                        scanning = [executor.submit(self.process_new_client,
                                                    addr, data)]
                        for future in as_completed(scanning):
                            future.result()
                    except:
                        error_handler(port=self.port)
                        continue
            except KeyboardInterrupt:
                print("Finishing...")
            finally:
                logging.debug("\n---------The program was closed.---------\n")
                self.ttl_timer.cancel()
                self.sock.close()
                executor.shutdown()

    def process_new_client(self, addr, data):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            id_ = data[:2]
            if self.cycle_processor.is_cycle(id_):
                raise CycleError
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", self.port))
            sock.settimeout(0.5)
            try:
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
                self.cycle_processor.delete_id(id_)
            except:
                error_handler(id_=id_)

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
