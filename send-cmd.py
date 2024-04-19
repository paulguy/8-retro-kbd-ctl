#!/usr/bin/env python

import sys
import os
import array

from lib.usb import Endpoint
from lib.util import BIT_MASKS
from lib.hiddev import HIDDEV

VENDOR_ID = "2dc8"
PRODUCT_ID = "5200"
INTERFACE_NUM = 2

def decode_args(args):
    vals = array.array('B')
    bit = 0
    num = 0
    for arg in args:
        num += 1
        try:
            byte = int(arg, base=16)
            if bit == 0:
                vals.append(byte)
            else:
                vals[-1] |= byte >> bit
                vals.append((byte << (8 - bit)) & 0xFF)
        except ValueError:
            if arg[0] == 'x':
                count = 0
                if len(arg) > 1:
                    count = int(arg[1:])
                return num, vals, count

            if bit == 0:
                vals.append(0)

            for num, char in enumerate(arg):
                match char:
                    case '.':
                        pass # already 0
                    case '#':
                        vals[-1] |= BIT_MASKS[bit]
                    case _:
                        raise ValueError(f"Unknown argument '{arg}'!")
                bit += 1
                bit %= 8
    return num, vals, -1

def generate_reports(hid, args):
    bufs = []
    pos = 0
    while pos < len(args):
        report_id = int(args[pos])

        num, vals, count = decode_args(args[pos+1:])
        pos += num + 1

        bufs.append((hid.generate_report(report_id, vals), count))

    return bufs

def usage():
    print(f"USAGE: {sys.argv[0]} <list|decode-raw <sequence>|send-raw <sequence>|listen>\n\n"
           "list - Get a list of reports, also update report cache.\n"
           "decode-raw - Decode a sequence given on the command-line.\n"
           "send-raw - Send a sequence given on the command-line.\n"
           "listen - Just listen forever.\n\n"
           "A sequence is one or a series of output reports.\n"
           "A single report may be given and the default will just be to send the report and listen forever.\n"
           "A report is given as a decimal report ID followed by any combination of hex octets or bits given as # for 1 and . for 0.\n"
           "Reports are separated by an x which may be paired with a number like x5, "
           "which is the number of packets to listen for before continuing.\n"
           "If there is no number, it's assumed to be a 0, which will not listen and just continue on sending the next packet.\n"
           "A negative value can be given to listen forever, but this isn't useful as it can just be left off at the end of the "
           "sequence to indicate listening forever.\n")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "list":
            with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM, force_no_cache=True) as hid:
                out_reports = hid.get_reports(Endpoint.ADDRESS_DIR_OUT)
                in_reports = hid.get_reports(Endpoint.ADDRESS_DIR_IN)

            print("Out Reports")
            for report in out_reports.keys():
                print(f"{report}: {out_reports[report].get_size()}bit {out_reports[report]}")
            print("In Reports")
            for report in in_reports.keys():
                print(f"{report}: {in_reports[report].get_size()}bit {in_reports[report]}")
        elif sys.argv[1] == "decode-raw":
            if len(sys.argv) > 2:
                with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM, try_no_open=True) as hid:
                    bufs = generate_reports(hid, sys.argv[2:])

                    for buf in bufs:
                        print(hid.decode(buf[0][0], buf[0][1:]))
                        if buf[1] < 0:
                            print("Listen forever")
                        elif buf[1] == 0:
                            print("Don't listen")
                        else:
                            print(f"Listen for {buf[1]} packets")
            else:
                usage()
        elif sys.argv[1] == "listen":
            with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as hid:
                hid.listen()
        elif sys.argv[1] == "send-raw":
            if len(sys.argv) > 2:
                with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as hid:
                    bufs = generate_reports(hid, sys.argv[2:])

                    for buf in bufs:
                        print(hid.decode(buf[0][0], buf[0][1:]))
                        hid.write(buf[0])
                        hid.listen(count=buf[1])
            else:
                usage()
        else:
            usage()
    else:
        usage()
