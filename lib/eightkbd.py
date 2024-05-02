import array
from enum import IntEnum

from .keys import get_hut_code_from_name, get_name_from_hut_code, KEY_DISABLE, DISABLE_NAME
from .util import arg_to_num

VENDOR_ID = 0x2dc8
PRODUCT_ID = 0x5200
INTERFACE_NUM = 2

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

CMD_SET_MACRO_NAME = 0x74
CMD_SET_MACRO = 0x76
CMD_MACRO_CONST = 0x01
CMD_MACRO_MORE = 0x01
CMD_MACRO_MORE_POS = 2

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
    if namebytes[-1] == 0:
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
