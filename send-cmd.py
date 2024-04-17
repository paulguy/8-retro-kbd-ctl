#!/usr/bin/env python

import sys
import os
import select
import fcntl
import ctypes
import array
import itertools

import pyudev
from ioctl_opt import IOR as _IOR
from ioctl_opt import IOC as _IOC

from lib.usb import HID, Endpoint
from lib.util import BIT_MASKS, bits_to_bytes

VENDOR_ID = "2dc8"
PRODUCT_ID = "5200"
INTERFACE_NUM = 2

# include/linux/hid.h
HID_MAX_DESCRIPTOR_SIZE = 4096

# include/linux/hidraw.h
class hidraw_report_descriptor(ctypes.Structure):
    _fields_ = [
        ('size', ctypes.c_uint),
        ('value', ctypes.c_ubyte * HID_MAX_DESCRIPTOR_SIZE),
    ]

class hidraw_devinfo(ctypes.Structure):
    _fields_ = [
        ('bustype', ctypes.c_uint),
        ('vendor', ctypes.c_short),
        ('product', ctypes.c_short),
    ]

# get report descriptor size
HIDIOCGDESCSIZE = _IOR(ord('H'), 0x01, ctypes.c_int)
# get report descriptor
HIDIOCGRDESC = _IOR(ord('H'), 0x02, hidraw_report_descriptor)
# get raw info
HIDIOCGRAWINFO = _IOR(ord('H'), 0x03, hidraw_devinfo)
# get raw name
def HIDIOCGRAWNAME(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x04, length)
# get physical address
def HIDIOCGRAWPHYS(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x05, length)
# send feature report
def HIDIOCSFEATURE(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x06, length)
# get feature report
def HIDIOCGFEATURE(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x07, length)
# get raw uniq ??
def HIDIOCGRAWUNIQ(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x08, length)
# send input report
def HIDIOCSINPUT(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x09, length)
# get input report
def HIDIOCGINPUT(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x0A, length)
# send output report
def HIDIOCSOUTPUT(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x0B, length)
# get output report
def HIDIOCGOUTPUT(length):
    return _IOC(ioctl_opt.IRC_READ, ord('H'), 0x0C, length)

def print_properties(device):
    for prop in device.properties:
        print(f"{prop}={device.properties[prop]}")

def find_hidraw_by_ids(udev, vendor, product, interface):
    for device in udev.list_devices(subsystem='hidraw'):
        # up from hidraw to hid-generic, usb_interface up to usb_device
        usbdev = device.parent.parent.parent
        if 'ID_VENDOR_ID' in usbdev.properties and \
           'ID_MODEL_ID' in usbdev.properties and \
           usbdev.properties['ID_VENDOR_ID'] == vendor and \
           usbdev.properties['ID_MODEL_ID'] == product:
            # i don't know how reliable this will be in the future, but
            # i could see no other way
            usbinterface = device.parent.parent.properties['DEVPATH']
            index = usbinterface.rindex(".")+1
            if int(usbinterface[index:]) == interface:
                return device
    return None

class HIDDEV:
    def __init__(self, vendor_id, product_id, interface_num):
        udev = pyudev.Context()

        device = find_hidraw_by_ids(udev, vendor_id, product_id, interface_num)

        self.fd = os.open(device.device_node, os.O_RDWR | os.O_NONBLOCK)

    def __enter__(self):
        return self.fd

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.close(self.fd)
        return False

def get_desc_from_device(fd):
    size = ctypes.c_uint()
    fcntl.ioctl(fd, HIDIOCGDESCSIZE, size)

    buf = hidraw_report_descriptor()
    buf.size = size
    fcntl.ioctl(fd, HIDIOCGRDESC, buf, True)

    return array.array('B', buf.value[:size.value])

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

def get_largest_report(reports):
    largest = 0
    for report in reports:
        size = reports[report].get_size()
        if size > largest:
            largest = size
    return largest

def generate_reports(reports, args):
    bufs = []
    pos = 0
    while pos < len(args):
        report_id = int(args[pos])

        # convert to bytes and add 1 for report ID
        try:
            bufsize = bits_to_bytes(reports[report_id].get_size()) + 1
        except KeyError:
            raise IndexError(f"Invalid report ID {report_id}, see list command for output reports.")

        buf = array.array('B', (report_id,))

        num, vals, count = decode_args(args[pos+1:])
        pos += num + 1

        buf.extend(vals)
        if len(buf) < bufsize:
            buf.extend(itertools.repeat(0, bufsize - len(buf)))
        bufs.append((buf, count))

    return bufs

def listen(fd, hid, in_reports, out_reports, count=-1):
    largest = get_largest_report(in_reports)
    out_largest = get_largest_report(out_reports)
    if out_largest > largest:
        largest = out_largest
    largest = bits_to_bytes(largest) + 1

    buf = array.array('B', itertools.repeat(0, largest))

    while count != 0:
        select.select((fd,), (), (), 1)
        data_read = 0
        try:
            data_read = os.readv(fd, (buf,))
        except BlockingIOError:
            pass
        if data_read > 0:
            report_id = buf[0]
            direction = Endpoint.ADDRESS_DIR_OUT
            if report_id in in_reports:
                direction = Endpoint.ADDRESS_DIR_IN
            print(hid.decode_interrupt(report_id, direction, buf[1:]))
        if count > 0:
            count -= 1

def get_hid_desc(fd=-1, cached=True):
    desc = array.array('B')
    fromfile = False

    if cached:
        try:
            with open("hid_desc.bin", "rb") as descfile:
                descfile.seek(0, os.SEEK_END)
                size = descfile.tell()
                descfile.seek(0, os.SEEK_SET)
                desc.fromfile(descfile, size)
                fromfile = True
        except FileNotFoundError:
            pass

    if len(desc) == 0:
        if fd < 0:
            return None
        desc = get_desc_from_device(fd)

    if not fromfile:
        with open("hid_desc.bin", "wb") as descfile:
            desc.tofile(descfile)

    hid = HID()
    hid.decode_desc(desc)

    return hid

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
            with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
                hid = get_hid_desc(fd, cached=False)

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
                # try to get the cached value first, otherwise try to get it from the device
                hid = get_hid_desc(-1)
                if hid is None:
                    with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
                        hid = get_hid_desc(fd)

                reports = hid.get_reports(Endpoint.ADDRESS_DIR_OUT)

                bufs = generate_reports(reports, sys.argv[2:])

                for buf in bufs:
                    print(hid.decode_interrupt(buf[0][0], Endpoint.ADDRESS_DIR_OUT, buf[0][1:]))
                    if buf[1] < 0:
                        print("Listen forever")
                    elif buf[1] == 0:
                        print("Don't listen")
                    else:
                        print(f"Listen for {buf[1]} packets")
            else:
                usage()
        elif sys.argv[1] == "listen":
            with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
                hid = get_hid_desc(fd)

                in_reports = hid.get_reports(Endpoint.ADDRESS_DIR_OUT)
                out_reports = hid.get_reports(Endpoint.ADDRESS_DIR_IN)

                listen(fd, hid, in_reports, out_reports)
        elif sys.argv[1] == "send-raw":
            if len(sys.argv) > 2:
                with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
                    hid = get_hid_desc(fd)

                    in_reports = hid.get_reports(Endpoint.ADDRESS_DIR_IN)
                    out_reports = hid.get_reports(Endpoint.ADDRESS_DIR_OUT)

                    bufs = generate_reports(out_reports, sys.argv[2:])

                    for buf in bufs:
                        print(hid.decode_interrupt(buf[0][0], Endpoint.ADDRESS_DIR_OUT, buf[0][1:]))

                        os.write(fd, buf[0])

                        listen(fd, hid, in_reports, out_reports, buf[1])
            else:
                usage()
        else:
            usage()
    else:
        usage()
