from .util import arg_to_num

HUT_KEYS = (
    "reserved-00", "errorrollover", "errorpostfail", "errorundefined",
    "a", "b", "c", "d", "e" ,"f" ,"g", "h", "i", "j", "k", "l", "m", "n", "o",
    "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "1", "2", "3", "4",
    "5", "6", "7", "8", "9", "0", "enter", "escape", "backspace", "tab",
    "spacebar", "-", "=", "[", "]", "\\", "non-us-#", ";", "'", "`", ",", ".",
    "/", "caps-lock", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9",
    "f10", "f11", "f12", "print-screen", "scroll-lock", "pause", "insert",
    "home", "page-up", "delete", "end", "page-down", "right-arrow",
    "left-arrow", "down-arrow", "up-arrow", "kp-num-lock", "kp/", "kp*", "kp-",
    "kp+", "kp-enter", "kp1", "kp2", "kp3", "kp4", "kp5", "kp6", "kp7", "kp8",
    "kp9", "kp0", "kp.", "non-us-\\", "menu", "power", "kp=", "f13", "f14",
    "f15", "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", "f24",
    "execute", "help", "sun-props", "select", "stop", "again", "undo", "cut",
    "copy", "paste", "find", "mute", "volume-up", "volume-down",
    "locking-caps-lock", "locking-num-lock", "locking-scroll-lock", "kp,",
    "as400-kp=", "intl-1", "intl-2", "intl-3", "intl-4", "intl-5", "intl-6",
    "intl-7", "intl-8", "intl-9", "lang-1", "lang-2", "lang-3", "lang-4",
    "lang-5", "lang-6", "lang-7", "lang-8", "lang-9", "alt-erase", "sysrq",
    "cancel", "clear", "prior", "return", "separator", "out", "oper",
    "clear/again", "crsel/props", "exsel", "reserved-a5", "reserved-a6",
    "reserved-a7", "reserved-a8", "reserved-a9", "reserved-aa", "reserved-ab",
    "reserved-ac", "reserved-ad", "reserved-ae", "reserved-af", "kp00",
    "kp000", "thousands-separator", "decimal-separator", "currency",
    "currency-subunit", "kp(", "kp)", "kp{", "kp}", "kp-tab", "kp-backspace",
    "kp-a", "kp-b", "kp-c", "kp-d", "kp-e", "kp-f", "kp-xor", "kp^", "kp%",
    "kp<", "kp>", "kp&", "kp&&", "kp|", "kp||", "kp:", "kp#", "kp-space",
    "kp@", "kp!", "kp-memory-store", "kp-memory-recall", "kp-memory-clear",
    "kp-memory-add", "kp-memory-subtract", "kp-memory-multiply",
    "kp-memory-divide", "kp-sign", "kp-clear", "kp-clear-entry", "kp-binary",
    "kp-octal", "kp-decimal", "kp-hexadecimal", "reserved-de", "reserved-df",
    "left-control", "left-shift", "left-alt", "left-win", "right-control",
    "right-shift", "right-alt", "right-win"
)

EIGHTKBD_KEY_NAMES = {
    0x6C: "modifier-a",
    0x6D: "modifier-b",
    0x6E: "external-ya",
    0x6F: "external-yb",
    0x70: "external-xa",
    0x71: "external-xb",
    0x72: "external-ba",
    0x73: "external-bb",
    0x74: "external-aa",
    0x75: "external-ab"
}
EIGHTKBD_NAME_KEYS = {}
def init_name_keys():
    for key in EIGHTKBD_KEY_NAMES.keys():
        EIGHTKBD_NAME_KEYS[EIGHTKBD_KEY_NAMES[key]] = key

EIGHTKBD_KEY_VALUES = {
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
EIGHTKBD_VALUE_KEYS = {}
def init_value_keys():
    for key in EIGHTKBD_KEY_VALUES.keys():
        if key != 0:
            EIGHTKBD_VALUE_KEYS[EIGHTKBD_KEY_VALUES[key]] = key

# TODO: complete this list
KEYS_UNASSIGNABLE = (0x00, 0x01, 0x02, 0x03, 0x78, 0x79, 0x7a, 0x85, 0x86, 0x9e)

# maybe not complete...
KEYS_MODIFIERS = (0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7)

DISABLE_NAME = "disabled"
KEY_DISABLE = 0

def get_name_from_key_code(key):
    code = EIGHTKBD_KEY_VALUES[key]
    if code == 0:
        return EIGHTKBD_KEY_NAMES[key]
    return HUT_KEYS[code]

def get_key_code_from_name(name):
    code = 0
    try:
        code = arg_to_num(name)
    except ValueError:
        pass
    if code == 0:
        try:
            # try to get the HUT name from the key name
            code = HUT_KEYS.index(name.lower())
        except ValueError:
            if len(EIGHTKBD_NAME_KEYS) == 0:
                init_name_keys()
            try:
                # if not, try to get the name from the keyboard's
                # custom key names
                code = EIGHTKBD_NAME_KEYS[name.lower()]
            except KeyError:
                raise ValueError(f"No such key {name}.")
    # see if the key is on the keyboard
    if code not in EIGHTKBD_KEY_VALUES:
        raise ValueError(f"Key {name} isn't on this keyboard.")
    return code

def get_hut_code_from_name(name):
    code = None
    try:
        code = arg_to_num(name)
    except ValueError:
        pass
    if code is not None:
        if code < 0 or code > len(HUT_KEYS):
            raise ValueError("Numeric value doesn't map to a named key.")
        else:
            return code
    if name.lower() == DISABLE_NAME:
        return KEY_DISABLE
    return HUT_KEYS.index(name.lower())

def get_mod_code_from_name(name):
    code = get_hut_code_from_name(name)
    if code not in KEYS_MODIFIERS:
        raise ValueError("Key is not a modifier.")
    return code
