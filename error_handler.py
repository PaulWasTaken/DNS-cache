import socket
import sys
import struct

from cycle_processor import CycleError


def error_handler(port=None, id_=None):
    info = sys.exc_info()
    type_ = info[0]
    if type_ == CycleError:
        print("I hope, you've made a mistake while choosing a "
              "server-forwarder, since you point to myself.")
    elif type_ == ConnectionError:
        print("Connection was closed by a host.")
    elif type_ == OSError:
        e = info[1]
        if sys.platform == "win32":
            win_oserror_handler(e, port)
        else:
            print(e)
    elif type_ == socket.timeout:
        print("The upper server hasn't answered.\n"
              "Query id: {}".format(struct.unpack("!H", id_)[0]))
    elif type_ == struct.error:
        print("Probably incorrect server response. Try another one.\n"
              "Query id: {}".format(struct.unpack("!H", id_)[0]))
    elif type_ == ValueError:
        print(info[1])
    elif type_ == NotImplementedError:
        print("{} type is not supported.".format(info[1]))


def win_oserror_handler(exception, port):
    code = exception.errno
    if code == 10035:
        pass
    elif code == 10048:
        print("%s is being used." % port)
    elif code == 10054:
        print("Connection was closed by a host.")
    else:
        print("Unknown return code. %d" % code)
