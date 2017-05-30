import argparse
from sys import platform

from server import DNSServer


def win_oserror_handler(exception, port):
    code = exception.errno
    if code == 10048:
        print("%s is being used." % port)
    else:
        print("Unknown return code. %d" % code)


def create_parser():
    _parser = argparse.ArgumentParser()
    _parser.add_argument("-f", "--forwarder", help="Set DNS server-forwarder.",
                         dest="server_info", default="10.0.0.1:53", type=str)
    _parser.add_argument("-p", "--port", help="Set DNS port.",
                         dest="port", default=53, type=int)
    _parser.add_argument("-d", "--debug", help="Enable debug mode.",
                         dest="debug", action="store_true")
    return _parser

if __name__ == "__main__":
    parser = create_parser()
    settings = parser.parse_args()
    try:
        DNSServer(settings, settings.debug).invoke()
    except OSError as e:
        if platform == "win32":
            win_oserror_handler(e, settings.port)
        else:
            print(e)
    #     print("Wrong address or port: " + str(e))
