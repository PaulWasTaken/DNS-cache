import argparse

from server import DNSServer


def create_parser():
    _parser = argparse.ArgumentParser()
    _parser.add_argument("-f", "--forwarder", help="Set DNS server-forwarder.",
                         dest="server_info", default="8.8.8.8:53", type=str)
    _parser.add_argument("-p", "--port", help="Set DNS port.",
                         dest="port", default=53, type=int)
    _parser.add_argument("-d", "--debug", help="Enable debug mode.",
                         dest="debug", action="store_true")
    return _parser

if __name__ == "__main__":
    parser = create_parser()
    settings = parser.parse_args()
    # try:
    DNSServer(settings, settings.debug).invoke()
    # except OSError:
    #     print("{port} port is being used.".format(port=settings.port))
