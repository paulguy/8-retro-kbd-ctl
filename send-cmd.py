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
from lib.util import BIT_MASKS

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

def get_desc(fd):
    size = ctypes.c_uint()
    fcntl.ioctl(fd, HIDIOCGDESCSIZE, size)

    buf = hidraw_report_descriptor()
    buf.size = size
    fcntl.ioctl(fd, HIDIOCGRDESC, buf, True)

    return array.array('B', buf.value[:size.value])

def decode_args(args):
    vals = array.array('B')
    bit = 0
    for arg in args:
        try:
            byte = int(arg, base=16)
            if bit == 0:
                vals.append(byte)
            else:
                vals[-1] |= byte >> bit
                vals.append((byte << (8 - bit)) & 0xFF)
        except ValueError:
            if bit == 0:
                vals.append(0)
            for char in arg:
                match char:
                    case '.':
                        pass # already 0
                    case '#':
                        vals[-1] |= BIT_MASKS[bit]
                    case x:
                        raise ValueError(f"Unknown character '{x}'!")
                bit += 1
                bit %= 8
    return vals

def get_largest_report(reports):
    largest = 0
    for report in reports:
        size = reports[report].get_size()
        if size > largest:
            largest = size
    return largest

def listen(fd, hid, in_reports, out_reports):
    largest = get_largest_report(in_reports)
    out_largest = get_largest_report(out_reports)
    if out_largest > largest:
        largest = out_largest

    buf = array.array('B', itertools.repeat(0, largest))

    while True:
        try:
            select.select((fd,), (), (), 1)
            data_read = os.readv(fd, (buf,))
            report_id = buf[0]
            direction = Endpoint.ADDRESS_DIR_OUT
            if report_id in in_reports:
                direction = Endpoint.ADDRESS_DIR_IN
            print(hid.decode_interrupt(report_id, direction, buf[1:]))
        except BlockingIOError:
            pass

def usage():
    print(f"USAGE: {sys.argv[0]} <list|send-raw <report_id> [data]>")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "list":
            with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
                desc = get_desc(fd)

                hid = HID()
                hid.decode_desc(desc)
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
                with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
                    desc = get_desc(fd)

                    hid = HID()
                    hid.decode_desc(desc)
                    reports = hid.get_reports(Endpoint.ADDRESS_DIR_OUT)
                    report_id = int(sys.argv[2])
                    if report_id not in reports:
                        print(f"{report_id} isn't a valid report ID, valid options are:", end='')
                        for report_id in reports.keys():
                            print(f" {report_id}", end='')
                        print()
                    else:
                        bufsize = reports[report_id].get_size()
                        # get buffer size in bytes
                        if bufsize % 8 > 0:
                            bufsize += 8
                        bufsize //= 8
                        buf = decode_args(sys.argv[3:])
                        if len(buf) < bufsize:
                            buf.extend(itertools.repeat(0, bufsize - len(buf)))
                        print(hid.decode_interrupt(report_id, Endpoint.ADDRESS_DIR_OUT, buf))
            else:
                usage()
        elif sys.argv[1] == "listen":
            with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
                desc = get_desc(fd)

                hid = HID()
                hid.decode_desc(desc)
                in_reports = hid.get_reports(Endpoint.ADDRESS_DIR_OUT)
                out_reports = hid.get_reports(Endpoint.ADDRESS_DIR_IN)

                listen(fd, hid, in_reports, out_reports)
        elif sys.argv[1] == "send-raw":
            if len(sys.argv) > 2:
                with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
                    desc = get_desc(fd)

                    hid = HID()
                    hid.decode_desc(desc)
                    in_reports = hid.get_reports(Endpoint.ADDRESS_DIR_IN)
                    out_reports = hid.get_reports(Endpoint.ADDRESS_DIR_OUT)

                    report_id = int(sys.argv[2])
                    if report_id not in out_reports:
                        print(f"{report_id} isn't a valid report ID, valid options are:", end='')
                        for report_id in out_reports.keys():
                            print(f" {report_id}", end='')
                        print()
                    else:
                        bufsize = out_reports[report_id].get_size()
                        # get buffer size in bytes
                        if bufsize % 8 > 0:
                            bufsize += 8
                        bufsize //= 8
                        buf = decode_args(sys.argv[3:])
                        if len(buf) < bufsize:
                            buf.extend(itertools.repeat(0, bufsize - len(buf)))
                        print(f"{hid.decode_interrupt(report_id, Endpoint.ADDRESS_DIR_OUT, buf)}")
                        os.write(fd, buf)

                        listen(fd, hid, in_reports, out_reports)
            else:
                usage()
        else:
            usage()
    else:
        usage()
