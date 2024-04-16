#!/usr/bin/env python

from dataclasses import dataclass
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

def _main(infile, verbose, count):
    # not device interfaces, capture interfaces
    interfaces = []
    last_urbs = []

    scanner = pcapng.FileScanner(infile)
    ctx = USBContext(verbose)
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

def usage():
    print(f"USAGE: {sys.argv[0]} <pcapng-file>\n\n" \
           "Decode HID traffic captured in to pcapng-file.\n" \
           "This is and will only ever be very barebones and only decode that\n" \
           "which is necessary for me to reverse engineer a HID communication\n" \
           "between the Windows software and keyboard.  This will probably never\n" \
           "be able to decode any arbitrary USB communication or even HID\n" \
           "communications.\n")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
    else:
        verbose = False
        if len(sys.argv) > 2 and sys.argv[2].lower() == "verbose":
            verbose = True
        with open(sys.argv[1], 'rb') as infile:
            _main(infile, verbose, -1)
