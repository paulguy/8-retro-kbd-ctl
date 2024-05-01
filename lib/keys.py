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

# these are specific to the 8bitdo but they have to be here.
KEY_DISABLE = 0
NO_MODIFIER = 0
DISABLE_NAME = "disabled"

def get_is_modifier(code, disablable=False):
    return (disablable and code == NO_MODIFIER) or \
           (code >= 0xE0 and code <= 0xE7)

def get_hut_code_from_name(name, disablable=False):
    code = None
    try:
        code = arg_to_num(name)
    except ValueError:
        pass
    if code is not None:
        if code < 0 or code > len(HUT_KEYS):
            raise ValueError(f"Numeric value {code} doesn't map to a named key.")
        else:
            return code
    if disablable and name.lower() == DISABLE_NAME:
        return KEY_DISABLE
    try:
        return HUT_KEYS.index(name.lower())
    except ValueError:
        raise ValueError(f"\"{name}\" is not a known key name.")

def get_name_from_hut_code(code, disablable=False):
    if code < 0 or code > len(HUT_KEYS):
        raise ValueError(f"Numeric value {code} doesn't map to a named key.")
    if disablable and code == KEY_DISABLE:
        return DISABLE_NAME
    return HUT_KEYS[code]

def get_mod_code_from_name(name):
    code = get_hut_code_from_name(name)
    if code not in KEYS_MODIFIERS:
        raise ValueError(f"Key {code} is not a modifier.")
    return code
