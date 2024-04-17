#!/usr/bin/env python

from dataclasses import dataclass
import array
import pcapng
import sys

from lib.usb import USBContext
from lib.util import str_hex, ts_to_sec

LOOKBEHIND_LENGTH = 10
MIN_DUP = 1

@dataclass
class HwInterface:
    link_type : int
    name : str

def str_urb(num, urb):
    return f"{num} {ts_to_sec(urb[1], urb[2])} {urb[0].decode()}"

def _main(pcapfile, verbose, count, loadfile=None, savefile=None):
    # not device interfaces, capture interfaces
    interfaces = []
    last_urbs = []

    ctx = USBContext(verbose)

    if loadfile is not None:
        state = []
        with open(loadfile, 'r') as stateinfile:
            for line in stateinfile.readlines():
                state.append(array.array('B', (int(byte, base=16) for byte in line.split())))
        ctx.set_state(state)
        print("State loaded")

    with open(pcapfile, 'rb') as infile:
        scanner = pcapng.FileScanner(infile)
        num = 1
        dups = 0
        for block in scanner:
            if isinstance(block, pcapng.blocks.SectionHeader):
                print("Section Header")
            elif isinstance(block, pcapng.blocks.InterfaceDescription):
                interfaces.append(HwInterface(block.link_type, block.options['if_name']))
                print(f"Interface Description {interfaces[-1].name}")
            elif isinstance(block, pcapng.blocks.EnhancedPacket):
                if verbose:
                    print(f"{interfaces[block.interface_id].name} {block.packet_len}", end='')
                    if block.captured_len < block.packet_len:
                        print(f" {block.captured_len}")
                    else:
                        print()
                else:
                    if block.captured_len < block.packet_len:
                        print("Incomplete packet!")
                #print(str_hex(block.packet_data))
                try:
                    last_urbs.append(ctx.parse_urb(block.packet_data))
                    duplicate = False
                    dups_count = 0
                    if len(last_urbs) > LOOKBEHIND_LENGTH:
                        for i in range(1, LOOKBEHIND_LENGTH//2):
                            for j in range(1, i):
                                if last_urbs[-j][0] == last_urbs[-(i+j)][0]:
                                    dups_count += 1
                            if dups_count == i:
                                duplicate = True
                        last_urbs = last_urbs[1:]
                    if verbose:
                        print(last_urbs[-1][0])
                    if duplicate:
                        dups += 1
                    else:
                        if dups > 0:
                            if dups <= MIN_DUP:
                                for i in range(-MIN_DUP-1, -1):
                                    print(str_urb(num+i+1, last_urbs[i]))
                            else:
                                print(f"(After {dups} duplicate patterns, last size {dups_count})")
                            dups = 0
                        print(str_urb(num, last_urbs[-1]))
                except Exception as e:
                    print(str_hex(block.packet_data))
                    raise e
                num += 1
            elif isinstance(block, pcapng.blocks.InterfaceStatistics):
                pass
            else:
                print("Unhandled block type")
                print(block)
                break
            if count >= 0:
                count -= 1
                if count == 0:
                    break

    if savefile is not None:
        state = ctx.get_state()
        with open(savefile, 'w') as stateoutfile:
            for item in state:
                for byte in item.rawdata:
                    stateoutfile.write(f" {byte:02X}")
                stateoutfile.write("\n")
        print("State saved")

ARGSTRS = ("verbose", "load", "save")

def scan_for_filename(args, used_indices):
    for num, arg in enumerate(args):
        if num not in used_indices and arg not in ARGSTRS:
            used_indices.append(num)
            return arg
    return None

def usage():
    print(f"USAGE: {sys.argv[0]} <verbose|save|load|FILENAME>\n\n" \
           "Decode HID traffic captured in to pcapng-file.\n" \
           "This is and will only ever be very barebones and only decode that\n" \
           "which is necessary for me to reverse engineer a HID communication\n" \
           "between the Windows software and keyboard.  This will probably never\n" \
           "be able to decode any arbitrary USB communication or even HID\n" \
           "communications.\n\n" \
           "A state may be saved and/or loaded, this will be a listing of packets\n" \
           "which are important for decoding other things, so for example an\n" \
           "incomplete capture may be used.\n\n" \
           "If verbose appears on the command line, verbose output will be set.\n" \
           "if save or load appear on the command line, the first argument that\n" \
           "isn't a flag will be used as the save or load filename, and that.\n" \
           "filename will no longer be a candidate.  The pcap file should be given\n" \
           "as the last filename after any state files.\n")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        verbose = False
        loadfile = None
        savefile = None
        used_indices = []
        good = True
        for arg in sys.argv[1:]:
            if arg.lower() == "verbose":
                verbose = True
            elif arg.lower() == "load":
                loadfile = scan_for_filename(sys.argv[1:], used_indices)
                if loadfile == None:
                    usage()
                    good = False
                    break
            elif arg.lower() == "save":
                savefile = scan_for_filename(sys.argv[1:], used_indices)
                if savefile == None:
                    usage()
                    good = False
                    break
        if good:
            pcapfile = scan_for_filename(sys.argv[1:], used_indices)
            if pcapfile == None:
                usage()
            else:
                _main(pcapfile, verbose, -1, loadfile, savefile)
