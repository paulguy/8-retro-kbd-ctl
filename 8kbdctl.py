#!/usr/bin/env python

import sys
import array
from enum import IntEnum

import lib.keys as keys
from lib.hiddev import HIDDEV
import lib.eightkbd as eightkbd
from lib.util import str_hex

def fetch_profile(fd):
    pass

def usage():
    print(f"USAGE: {sys.argv[0]} <command> [args]\n\n"
           "Command may be:\n"
           "list-in-codes - List possible codes which relate to keys on the keyboard and\n"
           "    their names.\n"
           "list-out-codes - List possible codes which a key may be assigned to and their\n"
           "    names.\n"
           "set-mapping <in-key> [mod-key] <out-key> - Set a mapping from in-key to\n"
           "out-key, with optional mod-key to be pressed at the same time.\n"
           "test-macro <name> <in-key> <repeats> <event>... - Test encoding a macro for in-key.\n"
           "Then print it.\n"
           "  for each event: <up/down> <out-key/mod-key> <delay in milliseconds>\n"
           "set-all-default - Restore all keys to defaults.")

def assemble_set_key(hid, from_key, to_key, mod_key=0):
    if not eightkbd.get_is_assignable(to_key, True):
        raise ValueError(f"Key code {to_key} is unassignable.")

    if keys.get_is_modifier(to_key):
        if mod_key != eightkbd.NO_MODIFIER:
            raise ValueError("Multiple modifier keys can't be specified.")
        mod_key = to_key
        to_key = 0

    if not keys.get_is_modifier(mod_key, True):
        raise ValueError("Key code {mod_key} is not a modifier.")

    buf = array.array('B', eightkbd.CMD_SET_KEY)
    buf.extend((from_key, eightkbd.SET_TYPE_KBD, mod_key, to_key))

    return hid.generate_report(eightkbd.OUT_ID, buf)

class MacroEventAction(IntEnum):
    DELAY = 0x0F
    PRESSED = 0x81
    RELEASED = 0x01
    MOD_PRESSED = 0x83
    MOD_RELEASED = 0x03

def parse_macro_args(args):
    events = []
    for i in range(0, len(args), 3):
        action, key, delay = args[i], keys.get_hut_code_from_name(args[i+1]), int(args[i+2])
        match action.lower():
            case 'down':
                if not eightkbd.get_is_assignable(key):
                    raise ValueError(f"Key code {key} is unassignable.")
                if keys.get_is_modifier(key):
                    events.append((MacroEventAction.MOD_PRESSED, key))
                else:
                    events.append((MacroEventAction.PRESSED, key))
            case 'up':
                if not eightkbd.get_is_assignable(key):
                    raise ValueError(f"Key code {key} is unassignable.")
                if keys.get_is_modifier(key):
                    events.append((MacroEventAction.MOD_RELEASED, key))
                else:
                    events.append((MacroEventAction.RELEASED, key))
            case x:
                raise ValueError(f"Invalid event type {x}.")
        if delay != 0:
            if delay < 0 or delay > 65535:
                raise ValueError("Delay must be 0 to 65535.")
            events.append((MacroEventAction.DELAY, delay))
    return events

def str_event_list(events):
    ret = ""
    for num, event in enumerate(events):
        match event[0]:
            case MacroEventAction.DELAY:
                ret += f"Delay: {event[1]} ms"
            case MacroEventAction.PRESSED:
                ret += f"Press: {keys.get_name_from_hut_code(event[1])}"
            case MacroEventAction.RELEASED:
                ret += f"Release: {keys.get_name_from_hut_code(event[1])}"
            case MacroEventAction.MOD_PRESSED:
                ret += f"Modifier Press: {keys.get_name_from_hut_code(event[1])}"
            case MacroEventAction.MOD_RELEASED:
                ret += f"Modifier Release: {keys.get_name_from_hut_code(event[1])}"
        if num < len(events) - 1:
            ret += ", "
    return ret

def generate_macro_data(repeats, events):
    if repeats < 0 or repeats > 65535:
        raise ValueError("Repeats must be 0 to 65535.")
    buf = array.array('B', (eightkbd.CMD_SET_MACRO_CONST,
                            repeats & 0xFF,
                            repeats >> 8 & 0xFF,
                            len(events)))
    for event in events:
        if event[0] == MacroEventAction.DELAY:
            buf.extend((event[0].value,
                        event[1] & 0xFF,
                        event[1] >> 8 & 0xFF))
        else:
            buf.extend((event[0].value,
                        event[1] & 0xFF,
                        0))
    return buf

def try_convert_name(name, bytes_len):
    # encode the string and chop it to fit
    namebytes = name.encode(eightkbd.NAME_ENCODING)[:bytes_len]
    try:
        # try to see if this works
        namebytes.decode(eightkbd.NAME_ENCODING)
    except UnicodeDecodeError:
        # try to cut off another byte...
        namebytes = namebytes[:-1]
        try:
            namebytes.decode(eightkbd.NAME_ENCODING)
        except UnicodeDecodeError:
            raise ValueError(f"Couldn't encode name \"{name}\", try to limit it to {bytes_len // 2} characters.")
    return namebytes

def split_macro_data(name, from_key, eventsbuf, packet_len):
    namebytes = try_convert_name(name, packet_len - 4)
    buf = array.array('B', (eightkbd.CMD_SET_MACRO_NAME,
                            from_key,
                            len(namebytes) & 0xFF,
                            len(namebytes) >> 8 & 0xFF))
    buf.extend(namebytes)

    bufs = [buf]

    pos = 0
    while pos < len(eventsbuf):
        this_len = 6 # every packet length
        items_len = 0
        if pos == 0:
            items_len += 4 # first packet additional
        this_items = (packet_len - this_len - items_len) // 3 # event length
        items_len += this_items * 3
        this_len += items_len
        more = 1
        if pos + items_len >= len(eventsbuf):
            items_len = len(eventsbuf) - pos
            more = 0
        buf = array.array('B', (eightkbd.CMD_SET_MACRO,
                                from_key,
                                more,
                                pos & 0xFF,
                                pos >> 8 & 0xFF,
                                items_len))
        buf.extend(eventsbuf[pos:pos+items_len])
        bufs.append(buf)
        pos += items_len
    return bufs

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
            for num in range(len(keys.HUT_KEYS)):
                if eightkbd.get_is_assignable(num, True):
                    print(f"{num}/0x{num:02X}: {keys.get_name_from_hut_code(num, True)}")
        elif sys.argv[1] == 'list-in-codes':
            for key in eightkbd.KEY_VALUES.keys():
                print(f"{key}/0x{key:02X}: {eightkbd.get_name_from_key_code(key)}")
        elif sys.argv[1] == 'set-mapping':
            if len(sys.argv) < 4:
                usage()
            else:
                from_key = eightkbd.get_key_code_from_name(sys.argv[2])
                mod_key = 0
                to_key = 0
                if len(sys.argv) > 4:
                    mod_key = keys.get_mod_code_from_name(sys.argv[3])
                    to_key = keys.get_hut_code_from_name(sys.argv[4], True)
                else:
                    to_key = keys.get_hut_code_from_name(sys.argv[3], True)
                with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                    report = assemble_set_key(hid, from_key, to_key, mod_key)
                    print(hid.decode(report[0], report[1:]))
                    hid.write(report)
                    success = [False]
                    hid.listen(-1, listen_response, success)
                    if not success[0]:
                        print("Device returned non-success.")
        elif sys.argv[1] == 'test-macro':
            if len(sys.argv) < 8:
                usage()
            else:
                name = sys.argv[2]
                from_key = eightkbd.get_key_code_from_name(sys.argv[3])
                repeats = int(sys.argv[4])
                events = parse_macro_args(sys.argv[5:])
                print(str_event_list(events))
                buf = generate_macro_data(repeats, events)
                print("Packets which would be sent:")
                bufs = split_macro_data(name, from_key, buf, 32)
                for buf in bufs:
                    print(str_hex(buf))
                    print()
        elif sys.argv[1] == 'set-all-default':
            with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                success = [False]
                for key in eightkbd.KEY_VALUES.keys():
                    report = assemble_set_key(hid, key, eightkbd.KEY_VALUES[key])
                    print(hid.decode(report[0], report[1:]))
                    hid.write(report)
                    hid.listen(-1, listen_response, success)
                    if not success[0]:
                        print("Device returned non-success.")
                        break
        else:
            usage()
