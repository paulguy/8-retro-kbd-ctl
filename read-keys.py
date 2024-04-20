#!/usr/bin/env python

import array

from lib.util import BIT_MASKS

# shenanigans
send_cmd = __import__("send-cmd", fromlist=('VENDOR_ID', 'PRODUCT_ID', 'INTERFACE_NUM'))
globals().update(vars(send_cmd))

OUT_ID = 82
IN_ID = 84
CMD_ENABLE_KEYMAP = (0x76, 0xa5)
CMD_DISABLE_KEYMAP = (0x76, 0xff)

def listen_callback(hid, last_report, report_id, data):
    if last_report[0] != (report_id, data):
        print(hid.decode(report_id, data))
        for num, byte in enumerate(data[3:]):
            for bit in range(8):
                if byte & BIT_MASKS[bit]:
                    val = (num * 8) + (7 - bit)
                    print(f" {val}/{val:02X}")
        last_report[0] = (report_id, data)
    return True

with HIDDEV(VENDOR_ID, PRODUCT_ID, INTERFACE_NUM) as hid:
    buf = hid.generate_report(OUT_ID, CMD_ENABLE_KEYMAP)
    print(hid.decode(buf[0], buf[1:]))
    hid.write(buf)

    last_report = [None]
    try:
        hid.listen(-1, listen_callback, last_report)
    except KeyboardInterrupt:
        buf = hid.generate_report(OUT_ID, CMD_DISABLE_KEYMAP)
        print(hid.decode(buf[0], buf[1:]))
        hid.write(buf)
