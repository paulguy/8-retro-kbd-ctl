import os
import select
import fcntl
import ctypes
import array
import itertools

import pyudev
from ioctl_opt import IOR as _IOR
from ioctl_opt import IOC as _IOC

from .usb import HID, Endpoint
from .util import bits_to_bytes

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

def find_hidraw_by_ids(udev, vendor, product, interface):
    vendor = f"{vendor:04x}"
    product = f"{product:04x}"
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

def generate_filename(vendor_id, product_id, interface_num):
    return f"{vendor_id:04x}_{product_id:04x}_{interface_num}.bin"

class HIDDEV:
    def raise_report_id_exception(self, report_id, direction=None):
        reports = self.all_reports
        if direction == Endpoint.ADDRESS_DIR_OUT:
            reports = self.out_reports
        if direction == Endpoint.ADDRESS_DIR_IN:
            reports = self.in_reports
        liststr = ""
        for report in sorted(reports.keys()):
            liststr += f" {report}"

        raise IndexError(f"Invalid report ID {report_id}, see list command for output reports. Valid options: {liststr}")

    def get_desc_from_device(self):
        size = ctypes.c_uint()
        fcntl.ioctl(self.fd, HIDIOCGDESCSIZE, size)

        buf = hidraw_report_descriptor()
        buf.size = size
        fcntl.ioctl(self.fd, HIDIOCGRDESC, buf, True)

        return array.array('B', buf.value[:size.value])

    def get_hid_desc(self, cached):
        desc = array.array('B')
        fromfile = False
        filename = generate_filename(self.vendor_id, self.product_id, self.interface_num)

        if cached:
            try:
                with open(filename, "rb") as descfile:
                    descfile.seek(0, os.SEEK_END)
                    size = descfile.tell()
                    descfile.seek(0, os.SEEK_SET)
                    desc.fromfile(descfile, size)
                    fromfile = True
            except FileNotFoundError:
                pass

        if self.fd is not None:
            desc = self.get_desc_from_device()
        else:
            return

        if not fromfile:
            with open(filename, "wb") as descfile:
                desc.tofile(descfile)

        self.hid.decode_desc(desc)
        self.have_desc = True

    def generate_report(self, report_id, data):
        # convert to bytes and add 1 for report ID
        try:
            bufsize = bits_to_bytes(self.all_reports[report_id].get_size()) + 1
        except KeyError:
            self.raise_report_id_exception(report_id)

        buf = array.array('B', (report_id,))

        buf.extend(data)
        if len(buf) < bufsize:
            buf.extend(itertools.repeat(0, bufsize - len(buf)))

        return buf

    def select(self, timeout):
        return len(select.select((self.fd,), (), (), timeout)[0]) > 0

    def read(self):
        size = os.readv(self.fd, (self.largest_buf,))
        return self.largest_buf[:size]

    def write(self, buf):
        return os.write(self.fd, buf)

    def listen(self, count=-1, callback=None, cb_data=None, timeout=None):
        while count != 0:
            try:
                if not self.select(timeout):
                    return False
            except KeyboardInterrupt:
                return False
            buf = self.read()
            if len(buf) > 0:
                report_id = buf[0]
                if callback is None:
                    print(self.decode(report_id, buf[1:]))
                else:
                    if not callback(self, cb_data, report_id, buf[1:]):
                        break
            if count > 0:
                count -= 1

        return True

    def get_reports(self, direction=None):
        if direction == Endpoint.ADDRESS_DIR_OUT:
            return self.out_reports
        elif direction == Endpoint.ADDRESS_DIR_IN:
            return self.in_reports
        return self.all_reports

    def get_report_direction(self, report_id):
        if report_id in self.out_reports:
            return Endpoint.ADDRESS_DIR_OUT
        if report_id in self.in_reports:
            return Endpoint.ADDRESS_DIR_IN
        self.raise_report_id_exception(report_id)

    def decode(self, report_id, data):
        return self.hid.decode_interrupt(report_id, self.get_report_direction(report_id), data)

    def __init__(self, vendor_id, product_id, interface_num, force_no_cache=False, try_no_open=False):
        self.fd = None
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.interface_num = interface_num
        self.hid = HID()

        self.have_desc = False

        if try_no_open:
            # can't force disuse of cache
            self.get_hid_desc(True)

        # if cache loading failed, try to open
        if not try_no_open or (try_no_open and not self.have_desc):
            udev = pyudev.Context()
            device = find_hidraw_by_ids(udev, vendor_id, product_id, interface_num)
            self.fd = os.open(device.device_node, os.O_RDWR | os.O_NONBLOCK)
            if force_no_cache:
                self.get_hid_desc(False)
            else:
                self.get_hid_desc(True)

        self.out_reports = self.hid.get_reports(Endpoint.ADDRESS_DIR_OUT)
        self.in_reports = self.hid.get_reports(Endpoint.ADDRESS_DIR_IN)
        self.all_reports = self.out_reports.copy()
        self.all_reports.update(self.in_reports)

        largest = 0
        for report in self.all_reports:
            size = self.all_reports[report].get_size()
            if size > largest:
                largest = size
        # +1 for report id
        self.largest_buf = array.array('B', itertools.repeat(0, bits_to_bytes(largest)+1))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            os.close(self.fd)
        return False
