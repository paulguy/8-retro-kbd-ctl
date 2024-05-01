#!/usr/bin/env python

import sys
import array
from enum import IntEnum
import itertools

import lib.keys as keys
from lib.hiddev import HIDDEV
import lib.eightkbd as eightkbd
from lib.util import str_hex, bits_to_bytes

KBD_TIMEOUT=5

def usage(args):
    print(f"USAGE: {args[0]} <command> [args]\n\n"
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

class KeyMapping:
    def __init__(self, to_key, mod_key=0):
        if not eightkbd.get_is_assignable(to_key, True):
            raise ValueError(f"Key code {to_key} is unassignable.")

        if keys.get_is_modifier(to_key):
            if mod_key != keys.NO_MODIFIER:
                raise ValueError("Multiple modifier keys can't be specified.")
            mod_key = to_key
            to_key = 0

        if not keys.get_is_modifier(mod_key, True):
            raise ValueError("Key code {mod_key} is not a modifier.")

        self.mod_key = mod_key
        self.to_key = to_key

    def __str__(self):
        if self.to_key == 0:
            if self.mod_key == 0:
                return keys.DISABLE_NAME
            else:
                raise ValueError("Internal Error: If to_key is 0, mod key must not be set.")
        else:
            if self.mod_key == 0:
                return keys.get_name_from_hut_code(self.to_key)
        return f"{keys.get_name_from_hut_code(self.mod_key)}+{keys.get_name_from_hut_code(self.to_key)}"

def assemble_set_key(hid, from_key, to_key, mod_key):
    mapping = KeyMapping(to_key, mod_key)

    buf = array.array('B', eightkbd.CMD_SET_KEY)
    buf.extend((from_key,
                eightkbd.SET_TYPE_KBD,
                mapping.mod_key,
                mapping.to_key))

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
    buf = array.array('B', (eightkbd.CMD_MACRO_CONST,
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

def split_macro_data(hid, name, from_key, eventsbuf):
    packet_len = bits_to_bytes(hid.get_reports()[eightkbd.OUT_ID].get_size())

    namebytes = eightkbd.try_encode_name(name, packet_len - 4)
    buf = array.array('B', (eightkbd.CMD_SET_MACRO_NAME,
                            from_key,
                            len(namebytes) & 0xFF,
                            len(namebytes) >> 8 & 0xFF))
    buf.extend(namebytes)

    namebuf = hid.generate_report(eightkbd.OUT_ID, buf) 

    bufs = []

    pos = 0
    while pos < len(eventsbuf):
        this_len = 6 # every packet length
        items_len = 0
        if pos == 0:
            items_len += 4 # first packet additional
        this_items = (packet_len - this_len - items_len) // 3 # event length
        items_len += this_items * 3
        this_len += items_len
        more = eightkbd.CMD_MACRO_MORE
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
        bufs.append(hid.generate_report(eightkbd.OUT_ID, buf))
        pos += items_len
    return namebuf, bufs

class KeyboardProfile:
    def __init__(self, name : str):
        self.name = name
        self.keys = {}
        self.macros = {}

    def set_key(self, key : int, mapping : KeyMapping):
        self.keys[key] = mapping

    def set_macro(self, key : int, macro):
        self.macros[key] = macro

    def __str__(self):
        ret = f"Profile Name: {self.name}\n"
        for key in self.keys.keys():
            ret += f"{eightkbd.get_name_from_key_code(key)}: {self.keys[key]}\n"
        return ret

def get_data_once(hid, data_return, report_id, data):
    print(hid.decode(report_id, data))

    if report_id == eightkbd.IN_ID:
        data_return.append(data)
        return False

    return True

def get_data_list(hid, data_return, report_id, data):
    print(hid.decode(report_id, data))

    if report_id == eightkbd.IN_ID:
        data_return.append(data)
        if data[-1] == 0:
            return False

    return True

def get_data_macrolist(hid, data_return, report_id, data):
    print(hid.decode(report_id, data))

    if report_id == eightkbd.IN_ID:
        data_return.append(data)
        if data[eightkbd.CMD_MACRO_MORE_POS] == 0:
            return False

    return True

def get_profile(hid):
    packet_len = bits_to_bytes(hid.get_reports()[eightkbd.OUT_ID].get_size())
    buf = array.array('B', itertools.repeat(0, packet_len))

    # get name
    buf[0] = eightkbd.CMD_GET_NAME
    print(hid.decode(eightkbd.OUT_ID, buf))
    hid.write(hid.generate_report(eightkbd.OUT_ID, buf))

    data_return = []
    if not hid.listen(-1, get_data_once, data_return, KBD_TIMEOUT):
        raise RuntimeError("Failed to get profile name from device.")

    str_size = data_return[0][1] | (data_return[0][2] << 8)
    name = eightkbd.decode_name(data_return[0][3:3+str_size])

    profile = KeyboardProfile(name)

    # get list of mappings
    buf[0] = eightkbd.CMD_GET_KEYS
    print(hid.decode(eightkbd.OUT_ID, buf))
    hid.write(hid.generate_report(eightkbd.OUT_ID, buf))

    data_return = []
    if not hid.listen(-1, get_data_list, data_return, KBD_TIMEOUT):
        raise RuntimeError("Failed to get key mappings list from device.")

    keys = []
    for item in data_return:
        for i in range(1, len(item)-2, 2):
            key = item[i]
            if key == 0:
                break
            keys.append(key)

    # get list of macros
    buf[0] = eightkbd.CMD_GET_MACROS
    print(hid.decode(eightkbd.OUT_ID, buf))
    hid.write(hid.generate_report(eightkbd.OUT_ID, buf))

    data_return = []
    if not hid.listen(-1, get_data_list, data_return, KBD_TIMEOUT):
        raise RuntimeError("Failed to get key mappings list from device.")

    macros = []
    for item in data_return:
        for i in range(1, len(item)-2, 4):
            macro = item[i]
            if macro == 0:
                break
            macros.append(macro)

    # get mappings
    buf[0] = eightkbd.CMD_GET_KEY

    for key in keys:
        buf[1] = key
        print(hid.decode(eightkbd.OUT_ID, buf))
        hid.write(hid.generate_report(eightkbd.OUT_ID, buf))

        data_return = []
        if not hid.listen(-1, get_data_once, data_return, KBD_TIMEOUT):
            raise RuntimeError("Failed to get key mapping from device.")

        if data_return[0][1] != key:
            raise ValueError(f"Got mapping for key {data_return[0][1]} instead of {key}?")
        if data_return[0][2] != eightkbd.SET_TYPE_KBD:
            raise ValueError(f"Unrecognized mapping type {data_return[0][2]}.")
        mapping = KeyMapping(data_return[0][4], data_return[0][3])
        profile.set_key(key, mapping)

    # get macro names
    buf[0] = eightkbd.CMD_GET_MACRO_NAME

    macronames = []

    for macro in macros:
        buf[1] = macro
        print(hid.decode(eightkbd.OUT_ID, buf))
        hid.write(hid.generate_report(eightkbd.OUT_ID, buf))

        data_return = []
        if not hid.listen(-1, get_data_once, data_return, KBD_TIMEOUT):
            raise RuntimeError("Failed to get macro name from device.")

        if data_return[0][1] != macro:
            raise ValueError(f"Got macro for key {data_return[0][1]} instead of {macro}?")

        str_size = data_return[0][2] | (data_return[0][3] << 8)
        macronames.append(eightkbd.decode_name(data_return[0][4:4+str_size]))

    return profile

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

def try_listen_success(hid):
    success = [False]
    if not hid.listen(-1, listen_response, success, KBD_TIMEOUT):
        raise RuntimeError("Didn't get a response packet.")
    elif not success[0]:
        raise RuntimeError("Device returned non-success.")

def main(args):
    if len(args) < 2:
        usage(args)
    else:
        if args[1] == 'list-out-codes':
            for num in range(len(keys.HUT_KEYS)):
                if eightkbd.get_is_assignable(num, True):
                    print(f"{num}/0x{num:02X}: {keys.get_name_from_hut_code(num, True)}")
        elif args[1] == 'list-in-codes':
            for key in eightkbd.KEY_VALUES.keys():
                print(f"{key}/0x{key:02X}: {eightkbd.get_name_from_key_code(key)}")
        elif args[1] == 'get-profile':
            with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                profile = get_profile(hid)
                print(profile)
        elif args[1] == 'set-mapping':
            if len(args) < 4:
                usage(args)
            else:
                from_key = eightkbd.get_key_code_from_name(args[2])
                mod_key = 0
                to_key = 0
                try:
                    if len(args) > 4:
                        mod_key = keys.get_mod_code_from_name(args[3])
                        to_key = keys.get_hut_code_from_name(args[4], True)
                    else:
                        to_key = keys.get_hut_code_from_name(args[3], True)
                except ValueError as e:
                    print(e)
                    return

                with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                    report = assemble_set_key(hid, from_key, to_key, mod_key)
                    print(hid.decode(report[0], report[1:]))
                    hid.write(report)
                    try_listen_success(hid)
        elif args[1] == 'test-macro':
            if len(args) < 8:
                usage(args)
            else:
                name = args[2]
                from_key = eightkbd.get_key_code_from_name(args[3])
                repeats = int(args[4])
                events = parse_macro_args(args[5:])
                print(str_event_list(events))
                buf = generate_macro_data(repeats, events)
                print("Packets which would be sent:")
                with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM, try_no_open=True) as hid:
                    bufs = split_macro_data(hid, name, from_key, buf)
                    for buf in bufs:
                        print(hid.decode(buf[0], buf[1:]))
        elif args[1] == 'set-macro':
            if len(args) < 8:
                usage(args)
            else:
                name = args[2]
                from_key = eightkbd.get_key_code_from_name(args[3])
                repeats = int(args[4])
                events = parse_macro_args(args[5:])
                buf = generate_macro_data(repeats, events)
                with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                    namebuf, bufs = split_macro_data(hid, name, from_key, buf)
                    print(hid.decode(namebuf[0], namebuf[1:]))
                    hid.write(namebuf)
                    try_listen_success(hid)
                    for buf in bufs:
                        print(hid.decode(buf[0], buf[1:]))
                        hid.write(buf)
                    try_listen_success(hid)
        elif args[1] == 'set-all-default':
            with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                for key in eightkbd.KEY_VALUES.keys():
                    report = assemble_set_key(hid, key, eightkbd.KEY_VALUES[key])
                    print(hid.decode(report[0], report[1:]))
                    hid.write(report)
                    try_listen_success(hid)
        else:
            usage(args)

if __name__ == '__main__':
    main(sys.argv)
