import array
import struct
from enum import IntEnum
import itertools

from .util import str_hex, bits_to_bytes
from .keys import get_hut_code_from_name, get_name_from_hut_code, get_is_modifier, KEY_DISABLE, NO_MODIFIER, DISABLE_NAME
from .util import arg_to_num

VENDOR_ID = 0x2dc8
PRODUCT_ID = 0x5200
INTERFACE_NUM = 2

KBD_TIMEOUT = 5

OUT_ID = 82
IN_ID = 84

# this might be wrong but matches what it looks like...
# otherwise, there's a 0 padding.
NAME_ENCODING = 'utf-16-be'

RESPONSE_CODE = 0xE4
RESPONSE_SUCCESS = 0x08

CMD_ENABLE_KEYMAP = (0x76, 0xa5)
CMD_DISABLE_KEYMAP = (0x76, 0xff)
CMD_SET_KEY = (0xFA, 0x03, 0x0C, 0x00, 0xAA, 0x09, 0x71)
SET_TYPE_MOUSE = 1
SET_TYPE_KBD = 7

CMD_SET_NAME = 0x70
CMD_SET_MACRO_NAME = 0x74
CMD_SET_MACRO = 0x76
CMD_MACRO_CONST = 0x01
CMD_MACRO_MORE = 0x01
CMD_MACRO_MORE_POS = 2
CMD_DELETE_MACRO = 0x77
DELETE_MACRO_CONST = 0x8c

CMD_GET_NAME = 0x80
CMD_GET_KEYS = 0x81
CMD_GET_MACROS = 0x82
CMD_GET_KEY = 0x83
CMD_GET_MACRO_NAME = 0x84
CMD_GET_MACRO = 0x86

class MacroEventAction(IntEnum):
    DELAY = 0x0F
    PRESSED = 0x81
    RELEASED = 0x01
    MOD_PRESSED = 0x83
    MOD_RELEASED = 0x03

KEY_NAMES = {
    0x6C: "modifier-b",
    0x6D: "modifier-a",
    0x6E: "external-ya",
    0x6F: "external-yb",
    0x70: "external-xa",
    0x71: "external-xb",
    0x72: "external-ba",
    0x73: "external-bb",
    0x74: "external-aa",
    0x75: "external-ab"
}
NAME_KEYS = {}
def try_init_name_keys():
    if len(NAME_KEYS) == 0:
        for key in KEY_NAMES.keys():
            NAME_KEYS[KEY_NAMES[key]] = key

KEY_VALUES = {
    # a - z
    0x04: 0x04, 0x05: 0x05, 0x06: 0x06, 0x07: 0x07, 0x08: 0x08,
    0x09: 0x09, 0x0A: 0x0A, 0x0B: 0x0B, 0x0C: 0x0C, 0x0D: 0x0D,
    0x0E: 0x0E, 0x0F: 0x0F, 0x10: 0x10, 0x11: 0x11, 0x12: 0x12,
    0x13: 0x13, 0x14: 0x14, 0x15: 0x15, 0x16: 0x16, 0x17: 0x17,
    0x18: 0x18, 0x19: 0x19, 0x1A: 0x1A, 0x1B: 0x1B, 0x1C: 0x1C,
    0x1D: 0x1D,
    # 0 - 9
    0x1E: 0x1E, 0x1F: 0x1F, 0x20: 0x20, 0x21: 0x21, 0x22: 0x22,
    0x23: 0x23, 0x24: 0x24, 0x25: 0x25, 0x26: 0x26, 0x27: 0x27,
    # the rest
    0x28: 0x28, 0x29: 0x29, 0x2A: 0x2A, 0x2B: 0x2B, 0x2C: 0x2C,
    0x2D: 0x2D, 0x2E: 0x2E, 0x2F: 0x2F, 0x30: 0x30, 0x31: 0x31,
    0x33: 0x33, 0x34: 0x34, 0x35: 0x35, 0x36: 0x36, 0x37: 0x37,
    0x38: 0x38, 0x39: 0x39, 0x3A: 0x3A, 0x3B: 0x3B, 0x3C: 0x3C,
    0x3D: 0x3D, 0x3E: 0x3E, 0x3F: 0x3F, 0x40: 0x40, 0x41: 0x41,
    0x42: 0x42, 0x43: 0x43, 0x44: 0x44, 0x45: 0x45, 0x46: 0x46,
    0x47: 0x47, 0x48: 0x48, 0x49: 0x49, 0x4A: 0x4A, 0x4B: 0x4B,
    0x4C: 0x4C, 0x4D: 0x4D, 0x4E: 0x4E, 0x4F: 0x4F, 0x50: 0x50,
    0x51: 0x51, 0x52: 0x52,
    # modifiers
    0x64: 0xE0, 0x65: 0xE1, 0x66: 0xE2, 0x67: 0xE3, 0x68: 0xE4,
    0x69: 0xE5, 0x6A: 0xE6, 0x6C: 0x00, 0x6D: 0x00,
    # external keys
    0x6E: 0x00, 0x6F: 0x00, 0x70: 0x00, 0x71: 0x00, 0x72: 0x00,
    0x73: 0x00, 0x74: 0x00, 0x75: 0x00
}
VALUE_KEYS = {}
def try_init_value_keys():
    if len(VALUE_KEYS) == 0:
        for key in KEY_VALUES.keys():
            if key != 0:
                VALUE_KEYS[KEY_VALUES[key]] = key

def check_success(buf):
    return buf[0] == RESPONSE_CODE and buf[1] == RESPONSE_SUCCESS

def get_is_assignable(code, disablable=False):
    return (disablable and code == KEY_DISABLE) or \
           (code >= 0x04 and code <= 0x78) or \
           (code >= 0xE0 and code <= 0xE7)

def get_name_from_key_code(key):
    code = KEY_VALUES[key]
    if code == 0:
        return KEY_NAMES[key]
    return get_name_from_hut_code(code)

def get_name_from_bitfield_code(code):
    if code >= 50:
        return get_name_from_key_code(code + 0x14)
    return get_name_from_key_code(code + 4)

def get_key_code_from_name(name):
    code = 0
    try:
        code = arg_to_num(name)
    except ValueError:
        pass
    if code == 0:
        try:
            # try to get the HUT name from the key name
            code = get_hut_code_from_name(name.lower())
            try_init_value_keys()
            # convert the HUT code to the key code.  This will
            # convert modifier HUT key values to the 8bitdo values
            try:
                code = VALUE_KEYS[code]
            except IndexError:
                pass
        except ValueError:
            try_init_name_keys()
            try:
                # if not, try to get the name from the keyboard's
                # custom key names
                code = NAME_KEYS[name.lower()]
            except KeyError:
                raise ValueError(f"No such key {name}.")
    # see if the key is on the keyboard
    if code not in KEY_VALUES:
        raise ValueError(f"Key {name} isn't on this keyboard.")
    return code

def try_encode_name(name, bytes_len):
    # encode the string and chop it to fit
    namebytes = name.encode(NAME_ENCODING)[:bytes_len]
    try:
        # try to see if this works
        namebytes.decode(NAME_ENCODING)
    except UnicodeDecodeError:
        # try to cut off another byte...
        namebytes = namebytes[:-1]
        try:
            namebytes.decode(NAME_ENCODING)
        except UnicodeDecodeError:
            raise ValueError(f"Couldn't encode name \"{name}\", try to limit it to {bytes_len // 2} characters.")

    namebytes = array.array('B', namebytes)

    # swap bytes for spaces, needed otherwise they return corrupt
    for i in range(0, len(namebytes)-1, 2):
        if namebytes[i] == 0x00 and namebytes[i+1] == 0x20:
            namebytes[i] = 0x20
            namebytes[i+1] = 0x00

    # trailing 0 is cut off
    if len(namebytes) % 2 == 1 and namebytes[-1] == 0:
        namebytes = namebytes[:-1]

    return namebytes

def decode_name(name):
    namebytes = array.array('B', name)

    # reattach cut off trailing 0
    if len(namebytes) % 2 == 1:
        namebytes.append(0)

    # swap bytes back
    for i in range(0, len(namebytes)-1, 2):
        if namebytes[i] == 0x20 and namebytes[i+1] == 0x00:
            namebytes[i] = 0x00
            namebytes[i+1] = 0x20

    return namebytes.tobytes().decode(NAME_ENCODING)

NAME_HDR = struct.Struct("<BH")
KEY_HDR = struct.Struct("<BBB")
# the set packet is very different from the get packet..
KEY_SET_HDR = struct.Struct("<BB")
MAP_KEY = struct.Struct("<BB")
MACRO_NAME_HDR = struct.Struct("<BBH")
MACRO_PKT_HDR = struct.Struct("<BBBHB")
MACRO_HDR = struct.Struct("<BHB")
MACRO_EVENT = struct.Struct("<BH")
MACRO_DELETE = struct.Struct("<BBB")

class KeyMapping:
    def __init__(self, to_key, mod_key):
        if not get_is_assignable(to_key, True):
            raise ValueError(f"Key code {to_key} is unassignable.")

        if get_is_modifier(to_key):
            if mod_key != NO_MODIFIER:
                raise ValueError("Multiple modifier keys can't be specified.")
            mod_key = to_key
            to_key = 0

        if not get_is_modifier(mod_key, True):
            raise ValueError("Key code {mod_key} is not a modifier.")

        self.mod_key = mod_key
        self.to_key = to_key

    def __str__(self):
        if self.to_key == 0:
            if self.mod_key == 0:
                return DISABLE_NAME
            else:
                return get_name_from_hut_code(self.mod_key)
        else:
            if self.mod_key == 0:
                return get_name_from_hut_code(self.to_key)
        return f"{get_name_from_hut_code(self.mod_key)}+{get_name_from_hut_code(self.to_key)}"

    def __eq__(self, other):
        if self.to_key == other.to_key and self.mod_key == other.mod_key:
            return True
        return False

    def get_set_array(self, from_key, packet_len):
        buf = array.array('B', CMD_SET_KEY)
        # TODO: figure out mouse stuff and expand this
        buf.extend(KEY_SET_HDR.pack(from_key, SET_TYPE_KBD))
        buf.extend(MAP_KEY.pack(self.mod_key, self.to_key))
        # extend to packet length
        buf.extend(itertools.repeat(0, packet_len - len(buf)))

        return buf

MAP_DISABLED = KeyMapping(KEY_DISABLE, KEY_DISABLE)

class KeyboardMacro:
    def __init__(self, name : str, repeats : int, packet_len : int):
        if repeats < 0 or repeats > 65535:
            raise ValueError("Repeats must be 0 to 65535.")
        self.packet_len = packet_len
        self.encoded_name = try_encode_name(name, self.packet_len - MACRO_NAME_HDR.size)
        self.name = name
        self.repeats = repeats
        self.events = []

    def set_name(self, name):
        self.encoded_name = try_encode_name(self.name, self.packet_len - MACRO_NAME_HDR.size)
        self.name = name

    def set_repeats(self, repeats):
        self.repeats = repeats

    def add_event(self, event, arg):
        match event:
            case MacroEventAction.DELAY:
                if arg < 0 or arg > 65535:
                    raise ValueError("Delay value {arg} out of range!")
                self.events.append((event, arg))
            case MacroEventAction.PRESSED:
                if arg < 0 or arg > 255:
                    raise ValueError("Key value {arg} out of range!")
                self.events.append((event, arg))
            case MacroEventAction.RELEASED:
                if arg < 0 or arg > 255:
                    raise ValueError("Key value {arg} out of range!")
                self.events.append((event, arg))
            case MacroEventAction.MOD_PRESSED:
                if arg < 0 or arg > 255:
                    raise ValueError("Key value {arg} out of range!")
                self.events.append((event, arg))
            case MacroEventAction.MOD_RELEASED:
                if arg < 0 or arg > 255:
                    raise ValueError("Key value {arg} out of range!")
                self.events.append((event, arg))
            case _:
                raise ValueError("Unsupported event {event}!")

    def add_events(self, events):
        for event in events:
            self.add_event(event[0], event[1])

    def clear_events(self):
        self.events = []

    def str_event_list(self):
        ret = ""
        for num, event in enumerate(self.events):
            match event[0]:
                case MacroEventAction.DELAY:
                    ret += f"Delay: {event[1]} ms\n"
                case MacroEventAction.PRESSED:
                    ret += f"Press: {get_name_from_hut_code(event[1])}\n"
                case MacroEventAction.RELEASED:
                    ret += f"Release: {get_name_from_hut_code(event[1])}\n"
                case MacroEventAction.MOD_PRESSED:
                    ret += f"Modifier Press: {get_name_from_hut_code(event[1])}\n"
                case MacroEventAction.MOD_RELEASED:
                    ret += f"Modifier Release: {get_name_from_hut_code(event[1])}\n"
        return ret

    def __str__(self):
        if self.repeats == 0:
            return f"Delete Macro"
        return f"Name: {self.name}\nRepeats: {self.repeats}\nEvents:\n{self.str_event_list()}"

    def __eq__(self, other):
        # if these are both delete macros, return equal
        if self.repeats == 0 and other.repeats == 0:
            return True
        # only compare data, not names
        if self.repeats != other.repeats:
            return False
        if len(self.events) != len(other.events):
            return False
        for num, event in enumerate(self.events):
            if event[0] != other.events[num][0] or event[1] != other.events[num][1]:
                return False
        return True

    def generate_macro_data(self):
        buf = array.array('B', MACRO_HDR.pack(CMD_MACRO_CONST,
                                              self.repeats,
                                              len(self.events)))
        for event in self.events:
            buf.extend(MACRO_EVENT.pack(event[0].value, event[1]))

        return buf

    def get_macro_packets(self, from_key):
        if self.repeats == 0:
            buf = array.array('B', MACRO_DELETE.pack(CMD_DELETE_MACRO,
                                                     from_key,
                                                     DELETE_MACRO_CONST))
            buf.extend(itertools.repeat(0, self.packet_len - len(buf)))
            return buf, ()

        namebuf = array.array('B', MACRO_NAME_HDR.pack(CMD_SET_MACRO_NAME,
                                                       from_key,
                                                       len(self.encoded_name)))
        namebuf.extend(self.encoded_name)
        # extend to packet length
        namebuf.extend(itertools.repeat(0, self.packet_len - len(namebuf)))

        if len(self.events) == 0:
            return namebuf, ()

        eventsbuf = self.generate_macro_data()

        bufs = []

        pos = 0
        while pos < len(eventsbuf):
            this_len = 6 # every packet length
            items_len = 0
            if pos == 0:
                items_len += 4 # first packet additional
            this_items = (self.packet_len - this_len - items_len) // 3 # event length
            items_len += this_items * 3
            this_len += items_len
            more = CMD_MACRO_MORE
            if pos + items_len >= len(eventsbuf):
                items_len = len(eventsbuf) - pos
                more = 0
            buf = array.array('B', MACRO_PKT_HDR.pack(CMD_SET_MACRO,
                                                      from_key,
                                                      more,
                                                      pos,
                                                      items_len))
            buf.extend(eventsbuf[pos:pos+items_len])
            # extend to packet length
            buf.extend(itertools.repeat(0, self.packet_len - len(buf)))
            bufs.append(buf)
            pos += items_len
        return namebuf, bufs

class KeyboardProfile:
    def __init__(self, name : str, packet_len : int):
        self.packet_len = packet_len
        self.encoded_name = try_encode_name(name, self.packet_len - NAME_HDR.size)
        self.name = name
        self.keys = {}
        self.macros = {}

    def set_all_default(self):
        self.keys = {}
        for key in KEY_VALUES.keys():
            self.keys[key] = KeyMapping(KEY_VALUES[key], KEY_DISABLE)
        self.macros = {}

    def set_name(self, name):
        self.encoded_name = try_encode_name(name, self.packet_len - NAME_HDR.size)
        self.name = name

    def get_name_packet(self):
        buf = array.array('B', NAME_HDR.pack(CMD_SET_NAME,
                                             len(self.encoded_name)))
        buf.extend(self.encoded_name)
        # extend to packet length
        buf.extend(itertools.repeat(0, self.packet_len - len(buf)))
        return (buf, True)

    def set_key(self, key : int, mapping : KeyMapping):
        self.keys[key] = mapping

    def get_key_packet(self, from_key):
        if from_key not in self.keys:
            raise IndexError(f"Key {from_key} is not a set macro.")

        return (self.keys[from_key].get_set_array(from_key, self.packet_len), True)

    def get_all_key_packets(self):
        packets = []
        for key in self.keys.keys():
            packets.append(self.get_key_packet(key))
        return packets

    def set_macro(self, key : int, macro : KeyboardMacro):
        self.macros[key] = macro

    def get_macro_packets(self, from_key):
        if from_key not in self.macros:
            raise IndexError(f"Key {from_key} is not a set macro.")

        packets = []

        namebuf, bufs = self.macros[from_key].get_macro_packets(from_key)
        packets.append((namebuf, True))
        for num, buf in enumerate(bufs):
            if num == len(bufs) - 1:
                packets.append((buf, True))
            else:
                packets.append((buf, False))

        return packets

    def get_all_macro_packets(self):
        packets = []
        for key in self.macros.keys():
            packets.extend(self.get_macro_packets(key))
        return packets

    def get_all_packets(self, with_name):
        packets = []
        if with_name:
            packets.append(self.get_name_packet())
        packets.extend(self.get_all_key_packets())
        packets.extend(self.get_all_macro_packets())
        return packets

    def __str__(self):
        ret = f"Profile Name: {self.name}\nKey Mappings:\n"
        for key in self.keys.keys():
            ret += f"{get_name_from_key_code(key)}: {self.keys[key]}\n"
        ret += "Macros:\n"
        for macro in self.macros.keys():
            ret += f"Key: {get_name_from_key_code(macro)}\n{self.macros[macro]}"
        return ret

def listen_response(hid, success, report_id, data):
    if success[0]:
        print(hid.decode(report_id, data))

    if report_id != IN_ID:
        # keep listening
        return True
    else:
        if check_success(data):
            success[1][0] = True
        else:
            success[1][0] = False
    return False

def get_data_once(hid, data_return, report_id, data):
    if data_return[0]:
        print(hid.decode(report_id, data))

    if report_id == IN_ID:
        data_return[1].append(data)
        return False

    return True

def get_data_list(hid, data_return, report_id, data):
    if data_return[0]:
        print(hid.decode(report_id, data))

    if report_id == IN_ID:
        data_return[1].append(data[:-1])
        if data[-1] == 0:
            return False

    return True

def get_data_macrolist(hid, data_return, report_id, data):
    if data_return[0]:
        print(hid.decode(report_id, data))

    if report_id == IN_ID:
        _, _, _, pos, size = MACRO_PKT_HDR.unpack(data[0:MACRO_PKT_HDR.size])
        if len(data_return[1]) == pos:
            data_return[1].extend(data[MACRO_PKT_HDR.size:MACRO_PKT_HDR.size+size])
        else:
            raise ValueError("Only support appending macro data buffers!")
        if data[CMD_MACRO_MORE_POS] == 0:
            return False

    return True

def decode_macro_data(macrobuf):
    _, repeats, count = MACRO_HDR.unpack(macrobuf[:MACRO_HDR.size])

    events = []
    for pos in range(MACRO_HDR.size,
                     MACRO_HDR.size+(count*MACRO_EVENT.size),
                     MACRO_EVENT.size):
        events.append(MACRO_EVENT.unpack(macrobuf[pos:pos+MACRO_EVENT.size]))

    return repeats, events

class EightKeyboard:
    def get_profile_from_device(self):
        buf = array.array('B', itertools.repeat(0, self.packet_len))

        # get name
        buf[0] = CMD_GET_NAME
        if self.verbose:
            print(self.hid.decode(OUT_ID, buf))
        self.hid.write(self.hid.generate_report(OUT_ID, buf))

        data_return = (self.verbose, [])
        if not self.hid.listen(-1, get_data_once, data_return, KBD_TIMEOUT):
            raise RuntimeError("Failed to get profile name from device.")

        _, str_size = NAME_HDR.unpack(data_return[1][0][:NAME_HDR.size])
        name = decode_name(data_return[1][NAME_HDR.size:NAME_HDR.size+str_size])

        self.profile = KeyboardProfile(name, self.packet_len)

        # get list of mappings
        buf[0] = CMD_GET_KEYS
        if self.verbose:
            print(self.hid.decode(OUT_ID, buf))
        self.hid.write(self.hid.generate_report(OUT_ID, buf))

        data_return = (self.verbose, [])
        if not self.hid.listen(-1, get_data_list, data_return, KBD_TIMEOUT):
            raise RuntimeError("Failed to get key mappings list from device.")

        mapped_keys = []
        for item in data_return[1]:
            for i in range(1, len(item)-2, 2):
                key = item[i]
                if key == 0:
                    break
                mapped_keys.append(key)

        # get list of macros
        buf[0] = CMD_GET_MACROS
        if self.verbose:
            print(self.hid.decode(OUT_ID, buf))
        self.hid.write(self.hid.generate_report(OUT_ID, buf))

        data_return = (self.verbose, [])
        if not self.hid.listen(-1, get_data_list, data_return, KBD_TIMEOUT):
            raise RuntimeError("Failed to get key mappings list from device.")

        macros = []
        for item in data_return[1]:
            for i in range(1, len(item)-2, 4):
                macro = item[i]
                if macro == 0:
                    break
                macros.append(macro)

        # get mappings
        buf[0] = CMD_GET_KEY

        for key in mapped_keys:
            buf[1] = key
            if self.verbose:
                print(self.hid.decode(OUT_ID, buf))
            self.hid.write(self.hid.generate_report(OUT_ID, buf))

            data_return = (self.verbose, [])
            if not self.hid.listen(-1, get_data_once, data_return, KBD_TIMEOUT):
                raise RuntimeError("Failed to get key mapping from device.")

            _, from_key, map_type = KEY_HDR.unpack(data_return[1][0][:KEY_HDR.size])

            if from_key != key:
                raise ValueError(f"Got mapping for key {from_key} instead of {key}?")
            if map_type != SET_TYPE_KBD:
                raise ValueError(f"Unrecognized mapping type {map_type}.")

            mod_key, to_key = MAP_KEY.unpack(data_return[1][0][KEY_HDR.size:KEY_HDR.size+MAP_KEY.size])

            mapping = KeyMapping(to_key, mod_key)
            self.profile.set_key(key, mapping)

        # get macro names
        buf[0] = CMD_GET_MACRO_NAME

        macronames = {}

        for macro in macros:
            buf[1] = macro
            if self.verbose:
                print(self.hid.decode(OUT_ID, buf))
            self.hid.write(self.hid.generate_report(OUT_ID, buf))

            data_return = (self.verbose, [])
            if not self.hid.listen(-1, get_data_once, data_return, KBD_TIMEOUT):
                raise RuntimeError("Failed to get macro name from device.")

            _, from_key, str_size = MACRO_NAME_HDR.unpack(data_return[1][0][:MACRO_NAME_HDR.size])

            if from_key != macro:
                raise ValueError(f"Got macro for key {from_key} instead of {macro}?")

            macronames[macro] = decode_name(data_return[1][0][MACRO_NAME_HDR.size:MACRO_NAME_HDR.size+str_size])

        # get macro definitions
        buf[0] = CMD_GET_MACRO

        for macro in macros:
            buf[1] = macro
            if self.verbose:
                print(self.hid.decode(OUT_ID, buf))
            self.hid.write(self.hid.generate_report(OUT_ID, buf))

            data_return = (self.verbose, array.array('B'))
            if not self.hid.listen(-1, get_data_macrolist, data_return, KBD_TIMEOUT):
                raise RuntimeError("Failed to get macro definition from device.")

            repeats, events = decode_macro_data(data_return[1])
            macro_obj = KeyboardMacro(macronames[macro], repeats, self.packet_len)
            macro_obj.add_events(events)

            self.profile.set_macro(macro, macro_obj)

    def __init__(self, hid, verbose=False, get_profile=True):
        # get_profile == False to force all changes
        self.verbose = verbose
        self.hid = hid
        self.packet_len = bits_to_bytes(self.hid.get_reports()[OUT_ID].get_size())
        self.delete_macro = KeyboardMacro("", 0, self.packet_len)
        if get_profile:
            self.get_profile_from_device()
            self.default_profile = KeyboardProfile("", self.packet_len)
            self.default_profile.set_all_default()
        else:
            self.default_profile = KeyboardProfile("", self.packet_len)
            self.profile = KeyboardProfile("", self.packet_len)
        self.new_profile = KeyboardProfile(self.profile.name, self.packet_len)

    def try_listen_success(self):
        success = (self.verbose, [False])
        if not self.hid.listen(-1, listen_response, success, KBD_TIMEOUT):
            raise RuntimeError("Didn't get a response packet.")
        elif not success[1][0]:
            raise RuntimeError("Device returned non-success.")

    def set_name(self, name):
        self.new_profile.set_name(name)

    def key_in_profile(self, from_key, mapping=None):
        if mapping is None:
            if (from_key in self.default_profile.keys and
                self.default_profile.keys[from_key] != MAP_DISABLED) or \
               (from_key in self.profile.keys and
                self.profile.keys[from_key] != MAP_DISABLED) or \
               (from_key in self.new_profile.keys and
                self.new_profile.keys[from_key] != MAP_DISABLED):
                return True
        else:
            if (from_key in self.default_profile.keys and
                self.default_profile.keys[from_key] == mapping) or \
               (from_key in self.profile.keys and
                self.default_profile.keys[from_key] == mapping) or \
               (from_key in self.new_profile.keys and
                self.new_profile.keys[from_key] == mapping):
                return True
        return False

    def set_key(self, from_key, to_key, mod_key=0):
        mapping = KeyMapping(to_key, mod_key)
        # if the key mapping is in the old profile, don't apply it.
        if not self.key_in_profile(from_key, mapping):
            self.new_profile.set_key(from_key, mapping)
            # if there's a macro set for this key, delete the macro
            if from_key in self.profile.macros or \
               from_key in self.new_profile.macros:
                self.new_profile.set_macro(from_key, self.delete_macro)

    def get_keys(self):
        return self.new_profile.keys.keys()

    def str_key(self, key):
        return str(self.new_profile.keys[key])

    def set_macro(self, from_key, name, repeats, events):
        new_macro = KeyboardMacro(name, repeats, self.packet_len)
        new_macro.add_events(events)
        # if the macro is in the old profile, don't apply it.
        # unless it's just a name change, as this can be sent in 1 packet
        if from_key not in self.profile.macros or \
           ((len(new_macro.events) != 0 and
             self.profile.macros[from_key] != new_macro) or
            (len(new_macro.events) == 0 and
             self.profile.macros[from_key].name != new_macro.name)):
            self.new_profile.set_macro(from_key, new_macro)
            # the normal app disables keys which have a macro set
            if self.key_in_profile(from_key):
                self.new_profile.set_key(from_key, MAP_DISABLED)
        elif from_key not in self.profile.macros or \
             (len(new_macro.events) != 0 and
              self.profile.macros[from_key] == new_macro and
              self.profile.macros[from_key].name != new_macro.name):
            # if the events would be the same but the name is just different
            # remove the events
            new_macro.clear_events()
            self.new_profile.set_macro(from_key, new_macro)

    def get_macros(self):
        return self.new_profile.macros.keys()

    def str_macro(self, macro):
        return str(self.new_profile.macros[macro])

    def get_key_packet(self, from_key):
        return self.new_profile.get_key_packet(from_key)

    def get_macro_packets(self, from_key):
        return self.new_profile.get_macro_packets(from_key)

    def str_profile(self):
        return str(self.profile)

    def str_new_profile(self):
        return str(self.new_profile)

    def get_all_packets(self):
        # don't force set name as this sets the name to an empty string,
        # disabling the profile completely
        if self.new_profile.name != self.profile.name:
            return self.new_profile.get_all_packets(True)
        return self.new_profile.get_all_packets(False)

    def set_all_default(self):
        # clear everything
        self.new_profile.set_all_default()

    def submit(self, test=False):
        packets = self.get_all_packets()
        for packet in packets:
            if self.verbose:
                print(self.hid.decode(OUT_ID, packet[0]))
            if not test:
                self.hid.write(self.hid.generate_report(OUT_ID, packet[0]))
            if packet[1]:
                if self.verbose:
                    print("Wait for response.")
                if not test:
                    self.try_listen_success()
