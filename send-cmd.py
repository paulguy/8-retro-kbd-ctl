#!/usr/bin/env python

import re
import pyudev

DEVICE_ID = "2dc8"
PRODUCT_ID = "5200"

def print_properties(device):
    for prop in device.properties:
        print(f"{prop}={device.properties[prop]}")

def find_hidraw_by_ids(udev, vendor, product):
    for device in udev.list_devices(subsystem='hidraw'):
        # up from hidraw to hid_generic, usb_interface up to usb_device
        usbdev = device.parent.parent.parent
        if 'ID_VENDOR_ID' in usbdev.properties and \
           'ID_MODEL_ID' in usbdev.properties and \
           usbdev.properties['ID_VENDOR_ID'] == vendor and \
           usbdev.properties['ID_MODEL_ID'] == product:
            return device

if __name__ == '__main__':
    udev = pyudev.Context()

    device = find_hidraw_by_ids(udev, DEVICE_ID, PRODUCT_ID)

    print(device.device_node)
