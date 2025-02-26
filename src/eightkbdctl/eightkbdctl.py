#!/usr/bin/env python

# TODO:
# Serialize/deseralize profiles (probably JSON)
# Send profile to device
# Record macros

import sys

from .lib import keys
from .lib.hiddev import HIDDEV
from .lib import eightkbd
MacroEventAction = eightkbd.MacroEventAction

def usage(exe):
    print(f"USAGE: {exe} [test|force|verbose]... <<command> [args]>...\n\n"
           "test - Just go through the motions but do everything except actually updating\n"
           "       the device.  The device will still be accessed to get the profile.\n"
           "force - Don't get the profile from the device, making all changes happen\n"
           "        even if they would be redundant.\n"
           "verbose - Get a lot of extra information about what's happening.\n\n"
           "Command may be:\n"
           "list-in-codes - List possible codes which relate to keys on the keyboard and\n"
           "    their names.\n"
           "list-out-codes - List possible codes which a key may be assigned to and their\n"
           "    names.\n"
           "get-profile - Get the profile from the device.\n"
           "set-name <name> - Set the profile name, as a quirk of the device, setting\n"
           "    the name to an empty string (\"\") will disable the profile button.\n"
           "set-key [<mod-key>+]<in-key> <out-key> - Set a mapping from in-key to\n"
           "    out-key, with optional mod-key to be pressed at the same time.\n"
           "set-macro <in-key> <name> <repeats> [events] - Set a macro to <in-key>.\n"
           "    <repeats> may be 0 to disable a macro, name and any events will be\n"
           "    accepted, but ignored, except end.\n"
           "    For each event: up|down <out-key/mod-key> <delay in milliseconds>\n"
           "                    - or -\n"
           "                    end\n"
           "down - Indicate a key press.\n"
           "up - Indicate a key release.\n"
           "end - Indicate the end of a macro, this is optional but necessary if\n"
           "      additional commands are to follow.\n"
           "set-all-default - Restore all keys to defaults.")

def parse_macro_args(args):
    events = []
    for i in range(0, len(args), 3):
        if args[i] == 'end':
            return i + 1, events

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
    return len(args), events

def main(args):
    exe = args[0]
    args = args[1:]
    
    test = False
    force = False
    verbose = False
    error = False

    if len(args) < 1:
        usage(exe)
    else:
        while True:
            arg = args[0]
            if len(arg) > 1:
                if arg == 'test':
                    test = True
                elif arg == 'force':
                    force = True
                elif arg == 'verbose':
                    verbose = True
                else:
                    break
            args = args[1:]

        cmd = args[0]
        if cmd == 'list-out-codes':
            for num in range(len(keys.HUT_KEYS)):
                if eightkbd.get_is_assignable(num, True):
                    print(f"{num}/0x{num:02X}: {keys.get_name_from_hut_code(num, True)}")
        elif cmd == 'list-in-codes':
            for key in eightkbd.KEY_VALUES.keys():
                print(f"{key}/0x{key:02X}: {eightkbd.get_name_from_key_code(key)}")
        elif cmd == 'get-profile':
            with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                kbd = eightkbd.EightKeyboard(hid, verbose)
                print(kbd.str_profile())
        else:
            with HIDDEV(eightkbd.VENDOR_ID, eightkbd.PRODUCT_ID, eightkbd.INTERFACE_NUM) as hid:
                # get_profile flag being False means force all changes
                kbd = eightkbd.EightKeyboard(hid, verbose, not force)

                while len(args) > 1:
                    cmd = args[0]
                    args = args[1:]
                    if cmd == 'set-name':
                        if len(args) < 1:
                            print("Not enough args for a name.")
                            error = True
                            break

                        kbd.set_name(args[0])
                        args = args[1:]
                    elif cmd == 'set-key':
                        if len(args) < 2:
                            print("Not enough arguments for a mapping.")
                            error = True
                            break

                        from_key = eightkbd.get_key_code_from_name(args[0])
                        mod_key = keys.KEY_DISABLE
                        to_key = keys.KEY_DISABLE
                        split = None
                        try:
                            split = args[1].index('+')
                        except ValueError:
                            pass
                        try:
                            # don't split on "kp+"
                            if split is not None and split != len(args[1]) - 1:
                                mod_key = keys.get_mod_code_from_name(args[1][:split])
                                to_key = keys.get_hut_code_from_name(args[1][split+1:], True)
                            else:
                                to_key = keys.get_hut_code_from_name(args[1], True)
                        except ValueError as e:
                            print(e)
                            return

                        kbd.set_key(from_key, to_key, mod_key)

                        args = args[2:]
                    elif cmd == 'set-macro':
                        # enough for 1 descriptor (name change)
                        # or a descriptor and single event which may just be 'end'
                        if len(args) < 3 or (len(args) > 4 and
                                             len(args) < 6):
                            print("Not enough arguments for a macro.")
                            error = True
                            break

                        from_key = eightkbd.get_key_code_from_name(args[0])
                        name = args[1]
                        try:
                            repeats = int(args[2])
                        except ValueError:
                            raise ValueError("Repeats must be an integer.")
                        count, events = parse_macro_args(args[3:])
                        args = args[count+3:]

                        kbd.set_macro(from_key, name, repeats, events)
                    elif cmd == 'set-all-default':
                        kbd.set_all_default()
                    else:
                        print(f"Unknown command {cmd}.")
                        error = True
                        break

                if error:
                    usage(exe)
                else:
                    if test:
                        print(kbd.str_new_profile())
                        if verbose:
                            print("These packets would be sent:")
                            kbd.submit(True)
                    else:
                        kbd.submit(False)

if __name__ == '__main__':
    main(sys.argv)
