#!/usr/bin/env python

import os
import array

# shenanigans
send_cmd = __import__("send-cmd", fromlist=('VENDOR_ID', 'PRODUCT_ID', 'INTERFACE_NUM', 'get_hid_desc', 'generate_report'))
globals().update(vars(send_cmd))

from lib.usb import Endpoint

OUT_ID = 82
IN_ID = 84
CMD_ENABLE_KEYMAP = (0x76, 0xa5)
CMD_DISABLE_KEYMAP = (0x76, 0xff)

def listen_callback(last_report, report_id, direction, data):
    if last_report[0] != (report_id, direction, data):
        print(hid.decode_interrupt(report_id, direction, data))
        last_report[0] = (report_id, direction, data)

with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as fd:
    hid = get_hid_desc(fd)

    in_reports = hid.get_reports(Endpoint.ADDRESS_DIR_IN)
    out_reports = hid.get_reports(Endpoint.ADDRESS_DIR_OUT)

    buf = generate_report(out_reports, OUT_ID, CMD_ENABLE_KEYMAP)
    print(hid.decode_interrupt(buf[0], Endpoint.ADDRESS_DIR_OUT, buf[1:]))
    os.write(fd, buf)

    last_report = [None]
    try:
        listen(fd, hid, in_reports, out_reports, -1, listen_callback, last_report)
    except KeyboardInterrupt:
        buf = generate_report(out_reports, OUT_ID, CMD_DISABLE_KEYMAP)
        print(hid.decode_interrupt(buf[0], Endpoint.ADDRESS_DIR_OUT, buf[1:]))
        os.write(fd, buf)
