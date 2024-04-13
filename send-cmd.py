#!/usr/bin/env python

import fcntl
import ctypes
import array
import itertools

import pyudev
from ioctl_opt import IOR as _IOR
from ioctl_opt import IOC as _IOC

from lib.usb import HID

DEVICE_ID = "2dc8"
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
# send input report
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
            usbinterface = device.parent.parent.properties['DEVPATH']
            index = usbinterface.rindex(".")+1
            if int(usbinterface[index:]) == interface:
                return device
    return None

def get_desc(fd):
    size = ctypes.c_uint()
    fcntl.ioctl(fd, HIDIOCGDESCSIZE, size)

    buf = hidraw_report_descriptor()
    buf.size = size
    fcntl.ioctl(fd, HIDIOCGRDESC, buf, True)

    return array.array('B', buf.value[:size.value])

if __name__ == '__main__':
    udev = pyudev.Context()

    device = find_hidraw_by_ids(udev, DEVICE_ID, PRODUCT_ID, INTERFACE_NUM)

    dev = open(device.device_node, 'rb')
    fd = dev.fileno()

    desc = get_desc(fd)

    hid = HID()
    hid.decode_desc(desc)
    print(hid)
