#!/usr/bin/env python

import sys
import array

import lib.keys as keys
from lib.hiddev import HIDDEV
import lib.eightkbd as eightkbd

def fetch_profile(fd):
    pass

def usage():
    pass

def assemble_set_key(hid, from_key, to_key, mod_key=0):
    if to_key in keys.KEYS_MODIFIERS:
        if mod_key != 0:
            raise ValueError("Multiple modifier keys can't be specified.")
        mod_key = to_key
        to_key = 0

    buf = array.array('B', eightkbd.CMD_SET_KEY)
    buf.extend((from_key, eightkbd.SET_TYPE_KBD, mod_key, to_key))

    return hid.generate_report(eightkbd.OUT_ID, buf)

def listen_response(hid, success, report_id, data):
    print(hid.decode(report_id, data))

    if report_id != eightkbd.IN_ID:
        # keep listening
        return True
    else:
        if eightkbd.check_success(data):
            success[0] = True
        else:
            success[0] = False
    return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        if sys.argv[1] == 'list-out-codes':
            for num, item in enumerate(keys.HUT_KEYS):
                print(f"{num}/0x{num:02X}: {item}")
        elif sys.argv[1] == 'list-in-codes':
            for key in keys.EIGHTKBD_KEY_VALUES.keys():
                print(f"{key}/0x{key:02X}: {keys.get_name_from_key_code(key)}")
        elif sys.argv[1] == 'set-mapping':
            if len(sys.argv) < 4:
                usage()
            else:
                with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                    from_key = keys.get_key_code_from_name(sys.argv[2])
                    mod_key = 0
                    to_key = 0
                    if len(sys.argv) > 4:
                        mod_key = keys.get_mod_code_from_name(sys.argv[3])
                        to_key = keys.get_hut_code_from_name(sys.argv[4])
                    else:
                        to_key = keys.get_hut_code_from_name(sys.argv[3])
                    report = assemble_set_key(hid, from_key, to_key, mod_key)
                    print(hid.decode(report[0], report[1:]))
                    hid.write(report)
                    success = [False]
                    hid.listen(-1, listen_response, success)
                    if not success[0]:
                        print("Device returned non-success.")
        elif sys.argv[1] == 'set-all-default':
            with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                success = [False]
                for key in keys.EIGHTKBD_KEY_VALUES.keys():
                    report = assemble_set_key(hid, key, keys.EIGHTKBD_KEY_VALUES[key])
                    print(hid.decode(report[0], report[1:]))
                    hid.write(report)
                    hid.listen(-1, listen_response, success)
                    if not success[0]:
                        print("Device returned non-success.")
                        break
