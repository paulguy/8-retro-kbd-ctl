#!/usr/bin/env python

import pcapng
import sys
from dataclasses import dataclass
import struct
import errno
import array

# not device interfaces, capture interfaces
interfaces = []
# any seen devices
devices = []
# present view of devices at any moment
devmap = {}

def chrbyte(char):
    if char < ord(' ') or char > ord('~'):
        return '.'
    return f"{char:c}"

def strbcd(val):
    return hex(val)[2:]

class UninterpretableDataException(Exception):
    pass

def str_hex(data):
    ret = ""
    for i in range(0, len(data)//16*16, 16):
        ret += f" {data[i]:02X} {data[i+1]:02X} {data[i+2]:02X} {data[i+3]:02X}" \
               f" {data[i+4]:02X} {data[i+5]:02X} {data[i+6]:02X} {data[i+7]:02X}" \
               f"-{data[i+8]:02X} {data[i+9]:02X} {data[i+10]:02X} {data[i+11]:02X}" \
               f" {data[i+12]:02X} {data[i+13]:02X} {data[i+14]:02X} {data[i+15]:02X}" \
               f"  {chrbyte(data[i])}{chrbyte(data[i+1])}{chrbyte(data[i+2])}{chrbyte(data[i+3])}" \
               f"{chrbyte(data[i+4])}{chrbyte(data[i+5])}{chrbyte(data[i+6])}{chrbyte(data[i+7])}" \
               f" {chrbyte(data[i+8])}{chrbyte(data[i+9])}{chrbyte(data[i+10])}{chrbyte(data[i+11])}" \
               f"{chrbyte(data[i+12])}{chrbyte(data[i+13])}{chrbyte(data[i+14])}{chrbyte(data[i+15])}"
        if i+16 <= len(data):
            ret += "\n"
    if len(data) % 16 != 0:
        ret += " "
        start = len(data) // 16 * 16
        for num in range(start, start+16):
            if num < len(data):
                ret += f"{data[num]:02X}"
            else:
                ret += "  "
            if num % 16 == 7:
                ret += "-"
            else:
                ret += " "
        ret += " "
        for num in range(start, len(data)):
            ret += chrbyte(data[num])
            if num % 16 == 7:
                ret += " "
    return ret

def get_better_string(orig, new):
    # if the new string is a truncated version of the original
    # just keep the original
    if orig.startswith(new):
        return False, orig
    # otherwise, apply the new string
    return True, new

def str_endpoint(busnum, devnum, endpoint):
    return f"{busnum}.{devnum}.{endpoint}"

def add_new_device(dev, dev_map):
    devices.append(dev)
    devmap[dev_map] = devices[-1]

def decode_string_desc(data):
    # don't need the length nor desc type
    return data[2:].decode('utf-16')

def decode_language_list(data):
    languages = []
    # don't need the length nor desc type
    for i in range(2, len(data), 2):
        languages.append(data[i] | (data[i+1] << 8))
    return languages

@dataclass
class HwInterface:
    link_type : int
    name : str

@dataclass(frozen=True)
class DevMap:
    bus : int
    device : int

class HID:
    hid : int
    country_code : int
    num_descriptor : int
    descriptor_type : int
    descriptor_length : int

    ITEM_SHORT_HDR_SIZE = 1
    ITEM_SIZE_MASK = 0x03
    ITEM_SIZE = {0x00: 0, 0x01: 1, 0x02: 2, 0x03: 4}

    ITEM_TYPE_MASK = 0x0C
    ITEM_TYPE_MAIN = 0x00
    ITEM_TYPE_GLOBAL = 0x04
    ITEM_TYPE_LOCAL = 0x08
    ITEM_TYPE_RESERVED = 0x0C

    ITEM_TAG_MASK = 0xF0
    ITEM_MAIN_INPUT = 0x80
    ITEM_MAIN_OUTPUT = 0x90
    ITEM_MAIN_FEATURE = 0xB0
    ITEM_MAIN_COLLECTION = 0xA0
    ITEM_MAIN_END_COLLECTION = 0xC0
    ITEM_GLOBAL_USAGE_PAGE = 0x00
    ITEM_GLOBAL_LOGICAL_MINIMUM = 0x10
    ITEM_GLOBAL_LOGICAL_MAXIMUM = 0x20
    ITEM_GLOBAL_PHYSICAL_MINIMUM = 0x30
    ITEM_GLOBAL_PHYSICAL_MAXIMUM = 0x40
    ITEM_GLOBAL_UNIT_EXPONENT = 0x50
    ITEM_GLOBAL_UNIT = 0x60
    ITEM_GLOBAL_REPORT_SIZE = 0x70
    ITEM_GLOBAL_REPORT_ID = 0x80
    ITEM_GLOBAL_REPORT_COUNT = 0x90
    ITEM_GLOBAL_PUSH = 0xA0
    ITEM_GLOBAL_POP = 0xB0
    ITEM_LOCAL_USAGE = 0x00
    ITEM_LOCAL_USAGE_MINIMUM = 0x10
    ITEM_LOCAL_USAGE_MAXIMUM = 0x20
    ITEM_LOCAL_DESIGNATOR_INDEX = 0x30
    ITEM_LOCAL_DESIGNATOR_MINIMUM = 0x40
    ITEM_LOCAL_DESIGNATOR_MAXIMUM = 0x50
    ITEM_LOCAL_STRING_INDEX = 0x70
    ITEM_LOCAL_STRING_MINIMUM = 0x80
    ITEM_LOCAL_STRING_MAXIMUM = 0x90
    ITEM_LOCAL_DELIMITER = 0xA0

    ITEM_MAIN_FLAG_CONSTANT = 0x01 # 0 - Data
    ITEM_MAIN_FLAG_VARIABLE = 0x02 # 0 - Array
    ITEM_MAIN_FLAG_RELATIVE = 0x04 # 0 - Absolute
    ITEM_MAIN_FLAG_WRAP = 0x08 # 0 - No-Wrap
    ITEM_MAIN_FLAG_NON_LINEAR = 0x10 # 0 - Linear
    ITEM_MAIN_FLAG_NO_PREFERRED = 0x20 # 0 - Preferred-State
    ITEM_MAIN_FLAG_NULL_STATE = 0x40 # 0 - No-Null-Position
    ITEM_MAIN_FLAG_VOLATILE = 0x80 # 0 - Non-Volatile
    # next byte
    ITEM_MAIN_FLAG_BUFFERED_BYTES = 0x01 # 0 - Bit-Field

    ITEM_COLLECTION_TYPE_PHYSICAL = 0x00
    ITEM_COLLECTION_TYPE_APPLICATION = 0x01
    ITEM_COLLECITON_TYPE_LOGICAL = 0x02
    ITEM_COLLECTION_TYPE_REPORT = 0x03
    ITEM_COLLECTION_TYPE_NAMED_ARRAY = 0x04
    ITEM_COLLECITON_TYPE_USAGE_SWITCH = 0x05
    ITEM_COLLECTION_TYPE_USAGE_MODIFIER = 0x06
    ITEM_COLLECTION_TYPE_VENDOR = 0x80

    ITEM_LONG_HDR_SIZE = 3
    ITEM_LONG_BYTE = 0xF7
    ITEM_LONG_SIZE = 1
    ITEM_LONG_TAG = 2

    # not at all exhaustive
    ITEM_USAGE_PAGE_MASK = 0xFFFF0000
    ITEM_USAGE_MASK = 0x0000FFFF
    ITEM_USAGE_PAGE_GENERIC_DESKTOP = 0x00010000
    ITEM_USAGE_PAGE_GENERIC_DEVICE_CONTROLS = 0x00060000
    ITEM_USAGE_PAGE_KEYBOARD = 0x00070000
    ITEM_USAGE_PAGE_LED = 0x00080000
    ITEM_USAGE_PAGE_BUTTON = 0x00090000
    ITEM_USAGE_PAGE_CONSUMER = 0x000C0000
    ITEM_USAGE_PAGE_UNICODE = 0x00100000
    ITEM_USAGE_PAGE_BARCODE_SCANNER = 0x008C0000

    ITEM_USAGE_GENERIC_DESKTOP_POINTER = 0x0001
    ITEM_USAGE_GENERIC_DESKTOP_MOUSE = 0x0002
    ITEM_USAGE_GENERIC_DESKTOP_X_AXIS = 0x0030
    ITEM_USAGE_GENERIC_DESKTOP_Y_AXIS = 0x0031
    ITEM_USAGE_GENERIC_DESKTOP_WHEEL = 0x0038

    ITEM_USAGE_CONSUMER_PAN = 0x0238

    # I guess python really does suck
    # specify endianness to ignore alignment?
    struct = struct.Struct("<BBHBBBH")

    def str_main_flags(data, input_item):
        if len(data) == 0:
            data = (0,)
        if data[0] & HID.ITEM_MAIN_FLAG_CONSTANT:
            ret = "Constant"
        else:
            ret = "Data"
        if data[0] & HID.ITEM_MAIN_FLAG_VARIABLE:
            ret += ":Variable"
        else:
            ret += ":Data"
        if data[0] & HID.ITEM_MAIN_FLAG_RELATIVE:
            ret += ":Relative"
        else:
            ret += ":Absolute"
        if data[0] & HID.ITEM_MAIN_FLAG_WRAP:
            ret += ":Wrap"
        else:
            ret += ":No-Wrap"
        if data[0] & HID.ITEM_MAIN_FLAG_NON_LINEAR:
            ret += ":Non-Linear"
        else:
            ret += ":Linear"
        if data[0] & HID.ITEM_MAIN_FLAG_NO_PREFERRED:
            ret += ":No-Preferred-State"
        else:
            ret += ":Preferred-State"
        if data[0] & HID.ITEM_MAIN_FLAG_NULL_STATE:
            ret += ":Null-State"
        else:
            ret += ":No-Null-State"
        if not input_item:
            if data[0] & HID.ITEM_MAIN_FLAG_VOLATILE:
                ret += ":Volatile"
            else:
                ret += ":Non-Volatile"
        if len(data) > 1:
            if data[0] & HID.ITEM_MAIN_FLAG_BUFFERED_BYTES:
                ret += ":Buffered-Bytes"
            else:
                ret += ":Bit-Field"
        return ret

    def str_collection_type(data):
        value = 0
        if len(data) > 0:
            value = data[0]
        if value >= HID.ITEM_COLLECTION_TYPE_VENDOR:
            return "Vendor-Defined"
        match value:
            case HID.ITEM_COLLECTION_TYPE_PHYSICAL:
                return "Physical"
            case HID.ITEM_COLLECTION_TYPE_APPLICATION:
                return "Application"
            case HID.ITEM_COLLECITON_TYPE_LOGICAL:
                return "Logical"
            case HID.ITEM_COLLECTION_TYPE_REPORT:
                return "Report"
            case HID.ITEM_COLLECTION_TYPE_NAMED_ARRAY:
                return "Named-Array"
            case HID.ITEM_COLLECITON_TYPE_USAGE_SWITCH:
                return "Usage-Switch"
            case HID.ITEM_COLLECTION_TYPE_USAGE_MODIFIER:
                return "Usage-Modifier"
        return "Unknown"

    # default values are 0
    def str_data_uint(data, high_16=False):
        value = 0
        for pos in range(len(data)):
            value |= data[pos] << (pos * 8)
        if high_16 and value <= 0xFFFF:
            value <<= 16
        return value

    def str_data_sint(data):
        match len(data):
            case 0:
                return 0
            case 1:
                return array.array('b', data)[0]
            case 2:
                return array.array('h', data)[0]
            case 3:
                return array.array('l', data+b'\0')[0] # top byte should be 0
            case 4:
                return array.array('l', data)[0]
        raise ValueError("Unimplemented interpreting signed ints larger than 4 bytes!")

    def str_usage(value):
        match value & HID.ITEM_USAGE_PAGE_MASK:
            case HID.ITEM_USAGE_PAGE_GENERIC_DESKTOP:
                ret = "Generic-Desktop"
                match value & HID.ITEM_USAGE_MASK:
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_POINTER:
                        ret += "/Pointer"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_MOUSE:
                        ret += "/Mouse"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_X_AXIS:
                        ret += "/X-Axis"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_Y_AXIS:
                        ret += "/Y-Axis"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_WHEEL:
                        ret += "/Wheel"
                return ret
            case HID.ITEM_USAGE_PAGE_GENERIC_DEVICE_CONTROLS:
                return "Generic-Device-Controls"
            case HID.ITEM_USAGE_PAGE_KEYBOARD:
                return "Keyboard"
            case HID.ITEM_USAGE_PAGE_LED:
                return "LED"
            case HID.ITEM_USAGE_PAGE_BUTTON:
                return "Button"
            case HID.ITEM_USAGE_PAGE_CONSUMER:
                ret = "Consumer"
                match value & HID.ITEM_USAGE_MASK:
                    case HID.ITEM_USAGE_CONSUMER_PAN:
                        ret += "/Application-Control-Pan"
                return ret
            case HID.ITEM_USAGE_PAGE_UNICODE:
                return "Unicode"
            case HID.ITEM_USAGE_PAGE_BARCODE_SCANNER:
                return "Barcode-Scanner"
        return "Unknown"

    def decode_desc(self, data):
        usage_page = 0

        pos = 0
        padding = " "
        while pos < len(data):
            pad_change = 0
            if data[pos] == self.ITEM_LONG_BYTE:
                size = data[pos+self.ITEM_LONG_SIZE]
                self.desc_str += f" Long {size}:{data[pos+self.ITEM_LONG_TAG]}"
                pos += size + self.ITEM_LONG_HDR_SIZE
            else:
                size = self.ITEM_SIZE[data[pos] & self.ITEM_SIZE_MASK]
                tag_str = "Unknown"
                data_str = ""
                match data[pos] & self.ITEM_TYPE_MASK:
                    case self.ITEM_TYPE_MAIN:
                        type_str = "Main"
                        match data[pos] & self.ITEM_TAG_MASK:
                            case self.ITEM_MAIN_INPUT:
                                tag_str = "Input"
                                data_str = HID.str_main_flags(data[pos+1:pos+1+size], True)
                            case self.ITEM_MAIN_OUTPUT:
                                tag_str = "Output"
                                data_str = HID.str_main_flags(data[pos+1:pos+1+size], False)
                            case self.ITEM_MAIN_FEATURE:
                                tag_str = "Feature"
                                data_str = HID.str_main_flags(data[pos+1:pos+1+size], False)
                            case self.ITEM_MAIN_COLLECTION:
                                tag_str = "Collection"
                                data_str = HID.str_collection_type(data[pos+1:pos+1+size])
                                pad_change = 1
                            case self.ITEM_MAIN_END_COLLECTION:
                                tag_str = "End-Collection"
                                pad_change = -1
                    case self.ITEM_TYPE_GLOBAL:
                        type_str = "Global"
                        match data[pos] & self.ITEM_TAG_MASK:
                            case self.ITEM_GLOBAL_USAGE_PAGE:
                                tag_str = "Usage-Page"
                                usage_page = HID.str_data_uint(data[pos+1:pos+1+size], True)
                                data_str = f"{usage_page:08X} {HID.str_usage(usage_page)}"
                                usage_page &= self.ITEM_USAGE_PAGE_MASK
                            case self.ITEM_GLOBAL_LOGICAL_MINIMUM:
                                tag_str = "Logical-Minimum"
                                data_str = HID.str_data_sint(data[pos+1:pos+1+size])
                            case self.ITEM_GLOBAL_LOGICAL_MAXIMUM:
                                tag_str = "Logical-Maximum"
                                data_str = HID.str_data_sint(data[pos+1:pos+1+size])
                            case self.ITEM_GLOBAL_PHYSICAL_MINIMUM:
                                tag_str = "Physical-Minimum"
                                data_str = HID.str_data_sint(data[pos+1:pos+1+size])
                            case self.ITEM_GLOBAL_PHYSICAL_MAXIMUM:
                                tag_str = "Physical-Maximum"
                                data_str = HID.str_data_sint(data[pos+1:pos+1+size])
                            case self.ITEM_GLOBAL_UNIT_EXPONENT:
                                tag_str = "Unit-Exponent"
                                data_str = f"*10^{HID.str_data_sint(data[pos+1:pos+1+size])}"
                            case self.ITEM_GLOBAL_UNIT:
                                tag_str = "Unit"
                                # not likely going to try...
                                data_str = f"{HID.str_data_sint(data[pos+1:pos+1+size]):08X}"
                            case self.ITEM_GLOBAL_REPORT_SIZE:
                                tag_str = "Report-Size"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_GLOBAL_REPORT_ID:
                                tag_str = "Report-ID"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_GLOBAL_REPORT_COUNT:
                                tag_str = "Report-Count"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_GLOBAL_PUSH:
                                tag_str = "Push"
                            case self.ITEM_GLOBAL_POP:
                                tag_str = "Pop"
                    case self.ITEM_TYPE_LOCAL:
                        type_str = "Local"
                        match data[pos] & self.ITEM_TAG_MASK:
                            case self.ITEM_LOCAL_USAGE:
                                tag_str = "Usage"
                                usage = HID.str_data_uint(data[pos+1:pos+1+size])
                                if usage <= self.ITEM_USAGE_MASK:
                                    usage |= usage_page
                                data_str = f"{usage:08X} {HID.str_usage(usage)}"
                            case self.ITEM_LOCAL_USAGE_MINIMUM:
                                tag_str = "Usage-Minimum"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_LOCAL_USAGE_MAXIMUM:
                                tag_str = "Usage-Maximum"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_LOCAL_DESIGNATOR_INDEX:
                                tag_str = "Designator-Index"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_LOCAL_DESIGNATOR_MINIMUM:
                                tag_str = "Designator-Minimum"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_LOCAL_DESIGNATOR_MAXIMUM:
                                tag_str = "Designator-Maximum"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_LOCAL_STRING_INDEX:
                                tag_str = "String-Index"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_LOCAL_STRING_MINIMUM:
                                tag_str = "String-Minimum"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_LOCAL_STRING_MAXIMUM:
                                tag_str = "String-Maximum"
                                data_str = HID.str_data_uint(data[pos+1:pos+1+size])
                            case self.ITEM_LOCAL_DELIMITER:
                                tag_str = "Delimiter"
                                data_str = "Closed-Set"
                                if HID.str_data_uint(data[pos+1:pos+1+size]):
                                    data_str = "Open-Set"
                    case self.ITEM_TYPE_RESERVED:
                        type_str = "Reserved"
                if pad_change < 0:
                    padding = padding[:-1]
                self.desc_str += f"\n{padding}{type_str}/{tag_str} {data_str}"
                if pad_change > 0:
                    padding += " "
                pos += size + self.ITEM_SHORT_HDR_SIZE

    def __init__(self, data):
        length, desc, self.hid, self.country_code, self.num_descriptors, self.descriptor_type, \
            self.descriptor_length = self.struct.unpack(data[:self.struct.size])
        self.desc_str = ""

    def __str__(self):
        return f"HID  ID: {strbcd(self.hid)} Country Code: {self.country_code}" \
               f" Descriptors: {self.num_descriptors} Type: {self.descriptor_type}" \
               f" Descriptor Length: {self.descriptor_length}{self.desc_str}"

class Endpoint:
    address : int
    attributes : int
    max_packet_size : int
    interval : int

    struct = struct.Struct("BBBBHB")

    ADDRESS_MASK = 0x0F
    ADDRESS_DIR_MASK = 0x80
    ADDRESS_DIR_OUT = 0x00
    ADDRESS_DIR_IN = 0x80

    ATTRIB_TYPE_MASK = 0x03
    ATTRIB_TYPE_CONTROL = 0x00
    ATTRIB_TYPE_ISOCHRONOUS = 0x01
    ATTRIB_TYPE_BULK = 0x02
    ATTRIB_TYPE_INTERRUPT = 0x03

    ATTRIB_ISO_SYNCH_MASK = 0x0C
    ATTRIB_ISO_SYNCH_NO = 0x00
    ATTRIB_ISO_SYNCH_ASYNC = 0x04
    ATTRIB_ISO_SYNCH_ADAPTIVE = 0x08
    ATTRIB_ISO_SYNCH_SYNC = 0x0C

    ATTRIB_ISO_USAGE_MASK = 0x30
    ATTRIB_ISO_USAGE_DATA = 0x00
    ATTRIB_ISO_USAGE_FEEDBACK = 0x10
    ATTRIB_ISO_USAGE_EXPLICIT = 0x20
    ATTRIB_ISO_USAGE_RESERVED = 0x30

    def get_address(self):
        return self.address & self.ADDRESS_MASK

    def get_direction(self):
        return self.address & self.ADDRESS_DIR_MASK

    def interrupt(self):
        # TODO: Interpret Interrupt/HID
        pass

    def __init__(self, data):
        length, desc, self.address, self.attributes, self.max_packet_size, self.interval = \
            self.struct.unpack(data[:self.struct.size])

    def __str__(self):
        addr_dir = "Out"
        if self.get_direction() == self.ADDRESS_DIR_IN:
            addr_dir = "In"
        attrib_iso_sync = ""
        attrib_iso_usage = ""
        attrib_type = "Control"
        match self.attributes & self.ATTRIB_TYPE_MASK:
            case self.ATTRIB_TYPE_ISOCHRONOUS:
                attrib_type = "Isochronous"
                match self.attributes & self.ATTRIB_ISO_SYNCH_MASK:
                    case self.ATTRIB_ISO_SYNCH_NO:
                        attrib_iso_sync = " No-Sync"
                    case self.ATTRIB_ISO_SYNCH_ASYNC:
                        attrib_iso_sync = " Async"
                    case self.ATTRIB_ISO_SYNCH_ADAPTIVE:
                        attrib_iso_sync = " Adaptive-Sync"
                    case self.ATTRIB_ISO_SYNCH_SYNC:
                        attrib_iso_sync = " Sync"
                match self.attribytes & self.ATTRIB_ISO_USAGE_MASK:
                    case self.ATTRIB_ISO_USAGE_DATA:
                        attrib_iso_usage = "Data-Endpoint"
                    case self.ATTRIB_ISO_USAGE_FEEDBACK:
                        attrib_iso_usage = "Feedback-Endpoint"
                    case self.ATTRIB_ISO_USAGE_EXPLICIT:
                        attrib_iso_usage = "Explicit-Feedback-Endpoint"
                    case self.ATTRIB_ISO_USAGE_RESERVED:
                        attrib_iso_usage = "Reserved"
            case self.ATTRIB_TYPE_BULK:
                attrib_type = "Bulk"
            case self.ATTRIB_TYPE_INTERRUPT:
                attrib_type = "Interrupt"
        return f"Endpoint  Address: {self.get_address()} {addr_dir}" \
               f" Attributes: {self.attributes} {attrib_type}{attrib_iso_sync}{attrib_iso_usage}" \
               f" Max Packet Size: {self.max_packet_size} Interval: {self.interval}"

class Interface:
    interface_id : int
    alternate_setting : int
    num_endpoints : int
    interface_class : int
    subclass : int
    protocol : int
    interface_string_id : int

    struct = struct.Struct("BBBBBBBBB")

    CLASS_HID = 3

    SUBCLASS_HID_NO_SUBCLASS = 0
    SUBCLASS_HID_BOOT = 1

    PROTOCOL_HID_NONE = 0
    PROTOCOL_HID_KEYBOARD = 1
    PROTOCOL_HID_MOUSE = 2

    def set_string(self, index, value):
        if self.interface_string_id == index:
            used, self.interface_string = get_better_string(self.interface_string, value)
            return used
        return False

    def get_size(self):
        hidsize = 0
        if self.interface_class == self.CLASS_HID:
            hidsize = HID.struct.size
        return len(self.endpoints) * Endpoint.struct.size + self.struct.size + hidsize

    def set_hid_report(self, data):
        self.hid.decode_desc(data)

    def get_hid_report(self):
        return self.hid

    def interrupt(self, urb):
        if self.interface_class == self.CLASS_HID:
            self.endpoints[urb.get_endpoint()].interrupt(urb)

    def __init__(self, data):
        length, desc, self.interface_id, self.alternate_setting, self.num_endpoints, \
            self.interface_class, self.subclass, self.protocol, \
            self.interface_string_id = self.struct.unpack(data[:self.struct.size])
        self.endpoints = {}
        pos = self.struct.size
        if self.interface_class == self.CLASS_HID:
            self.hid = HID(data[pos:])
            pos += HID.struct.size
        else:
            raise UninterpretableDataException(f"Unknown interface class {self.interface_class}")
        for j in range(self.num_endpoints):
            endpoint = Endpoint(data[pos:])
            self.endpoints[endpoint.get_address()] = endpoint
            pos += Endpoint.struct.size
        self.interface_string = ""

    def __str__(self):
        subclass_str = " Unknown"
        protocol_str = " Unknown"
        if self.interface_class == self.CLASS_HID:
            match self.subclass:
                case self.SUBCLASS_HID_NO_SUBCLASS:
                    subclass_str = " No Subclass"
                case self.SUBCLASS_HID_BOOT:
                    subclass_str = " Boot"
            match self.protocol:
                case self.PROTOCOL_HID_NONE:
                    protocol_str = " None"
                case self.PROTOCOL_HID_KEYBOARD:
                    protocol_str = " Keyboard"
                case self.PROTOCOL_HID_MOUSE:
                    protocol_str = " Mouse"
        ret = f"Interface  ID: {self.interface_id} Alternate Setting: {self.alternate_setting}" \
              f" Endpoints: {self.num_endpoints} Class: {self.interface_class}" \
              f" Subclass: {self.subclass}{subclass_str} Protocol: {self.protocol}{protocol_str}"
        if len(self.interface_string) == 0:
            ret += f" Interface String Index: {self.interface_string_id}"
        else:
            ret += f" Interface String: \"{self.interface_string}\""
        if self.interface_class == self.CLASS_HID:
            ret += f"\n{self.hid}"
        for endpoint in self.endpoints.keys():
            ret += f"\n{self.endpoints[endpoint]}"
        return ret

class Configuration:
    total_length : int
    num_interfaces : int
    configuration_id : int
    configuration_string_id : int
    attributes : int
    max_power : int

    struct = struct.Struct("BBHBBBBB")

    ATTRIB_SELF_POWERED = 0x40
    ATTRIB_REMOTE_WAKEUP = 0x20

    def __init__(self, data):
        length, desc, self.total_length, self.num_interfaces, self.configuration_id, \
            self.configuration_string_id, self.attributes, self.max_power \
            = self.struct.unpack(data[:self.struct.size])
        self.interfaces = {}
        if len(data) >= self.total_length - URB.SIZE:
            # decode following interfaces
            pos = self.struct.size
            for i in range(self.num_interfaces):
                interface = Interface(data[pos:])
                self.interfaces[interface.interface_id] = interface
                pos += interface.get_size()
        self.configuration_string = ""

    def set_string(self, index, value):
        found = False
        if self.configuration_string_id == index:
            found, self.configuration_string = get_better_string(self.configuration_string, value)

        for interface in self.interfaces.keys():
            if self.interfaces[interface].set_string(index, value):
                found = True
        return found

    def set_hid_report(self, interface, data):
        self.interfaces[interface].set_hid_report(data)

    def get_hid_report(self, interface):
        return self.interfaces[interface].get_hid_report()

    def interrupt(self, urb):
        for iface in self.interfaces:
            if iface.interface_id == interface:
                iface.interrupt(urb)

    def __str__(self):
        ret = f"Configuration  Total Length: {self.total_length} Interfaces: {self.num_interfaces}" \
              f" Num: {self.configuration_id}"
        if len(self.configuration_string) == 0:
            ret += f" Configuration String Index: {self.configuration_string_id}"
        else:
            ret += f" Configuration String: \"{self.configuration_string}\""
        ret += f" Attributes: {self.attributes:04X}"
        if self.attributes & self.ATTRIB_SELF_POWERED:
            ret += f" Self-Powered"
        if self.attributes & self.ATTRIB_REMOTE_WAKEUP:
            ret += f" Remote-Wakeup"
        ret += f" Max Power: {self.max_power*2}mA"
        for interface in self.interfaces.keys():
            ret += f"\n{self.interfaces[interface]}"
        return ret

class InterruptNoData:
    def __init__(self, direction):
        self.direction = direction

    def __str__(self):
        return f"Interrupt {self.direction} No Data"

class InterruptAcknowledge:
    def __init__(self, direction):
        self.direction = direction

    def __str__(self):
        return f"Interrupt {self.direction} Acknowledge"

class InterruptUnknown:
    def __init__(self, direction, data):
        self.direction = direction
        self.data = data

    def __str__(self):
        return f"Interrupt {self.direction} Unknown\n{str_hex(self.data)}"

class Device:
    busnum : int
    devnum : int
    usb : int
    dev_class : int
    sub_class : int
    protocol : int
    max_packet_size : int
    vendor : int
    product : int
    device : int
    # _string values start with a descriptor index which may be filled later
    manufacturer_string_id : int
    product_string_id : int
    serial_number_string_id : int
    num_configs : int

    struct = struct.Struct("BBHBBBBHHHBBBB")

    def __init__(self, data):
        length, desc, self.usb, self.dev_class, self.sub_class, self.protocol, \
            self.max_packet_size, self.vendor, self.product, \
            self.device, self.manufacturer_string_id, \
            self.product_string_id, self.serial_number_string_id, \
            self.num_configs = self.struct.unpack(data[:self.struct.size])
        self.configurations = {}
        self.manufacturer_string = ""
        self.product_string = ""
        self.serial_number_string = ""
        self.configuration = None

    def add_configuration(self, config):
        # don't replace existing configuration objects, unless they
        # have no interfaces yet
        if config.configuration_id not in self.configurations or \
           len(self.configurations[config.configuration_id].interfaces) == 0:
            self.configurations[config.configuration_id] = config

    def set_configuration(self, num):
        self.configuration = num

    def set_string(self, index, value):
        found = False
        if self.manufacturer_string_id == index:
            found, self.manufacturer_string = get_better_string(self.manufacturer_string, value)
        if self.product_string_id == index:
            used, self.product_string = get_better_string(self.product_string, value)
            if used:
                found = True
        if self.serial_number_string_id == index:
            used, self.serial_number_string = get_better_string(self.serial_number_string, value)
            if used:
                found = True
        for config in self.configurations.keys():
            if self.configurations[config].set_string(index, value):
                found = True
        return found

    def set_hid_report(self, interface, data):
        self.configurations[self.configuration].set_hid_report(interface, data)

    def get_hid_report(self, interface):
        return self.configurations[self.configuration].get_hid_report(interface)

    def interrupt(self, urb, prev):
        if urb.direction() == URB.ENDPOINT_DIR_IN:
            if len(urb.data) == 0:
                if prev.xfer_type == URB.XFER_TYPE_INTERRUPT and \
                   prev.direction() == URB.ENDPOINT_DIR_IN and \
                   urb.urb_type == URB.URB_TYPE_SUBMIT:
                    return InterruptAcknowledge("In")
                else:
                    return InterruptNoData("In")
            return InterruptUnknown("In", urb.data)
        else: # Out
            if len(urb.data) == 0:
                if prev.xfer_type == URB.XFER_TYPE_INTERRUPT and \
                   prev.direction() == URB.ENDPOINT_DIR_OUT and \
                   urb.urb_type == URB.URB_TYPE_COMPLETE:
                    return InterruptAcknowledge("Out")
                else:
                    return InterruptNoData("Out")
        return InterruptUnknown("Out", urb.data)

    def __eq__(self, other):
        # I don't know the official way to compare devices, and the serial number isn't guaranteed to be known yet
        return self.vendor == other.vendor and self.product == other.product and self.device == other.device

    def __str__(self):
        ret = f"Device  USB Spec: {strbcd(self.usb)} Class: {self.dev_class} Subclass: {self.sub_class}" \
              f" Protocol: {self.protocol} Max Packet Size: {self.max_packet_size} Vendor: {self.vendor:04X}" \
              f" Product: {self.product:04X} Device Ver.: {strbcd(self.device)}"
        if len(self.manufacturer_string) == 0:
            ret += f" Manufacturer String Index: {self.manufacturer_string_id}"
        else:
            ret += f" Manufacturer String: \"{self.manufacturer_string}\""
        if len(self.product_string) == 0:
            ret += f" Product String Index: {self.product_string_id}"
        else:
            ret += f" Product String: \"{self.product_string}\""
        if len(self.serial_number_string) == 0:
            ret += f" Serial Number String Index: {self.serial_number_string_id}"
        else:
            ret += f" Serial Number String String: \"{self.serial_number_string}\""
        ret += f" Number of Configurations: {self.num_configs}"
        for config in self.configurations.keys():
            ret += f"\n{self.configurations[config]}"
        return ret

class SetupURB:
    bmRequestType : int
    bRequest : int
    wValue : int
    wIndex : int
    wLength : int

    struct = struct.Struct("BBHHH")

    parent : "URB"

    TYPE_DIR_MASK = 0x80
    TYPE_DIR_HOST_TO_DEVICE = 0x00
    TYPE_DIR_DEVICE_TO_HOST = 0x80

    TYPE_MASK = 0x60
    TYPE_STANDARD = 0x00
    TYPE_CLASS = 0x20
    TYPE_VENDOR = 0x40
    TYPE_RESERVED = 0x60

    TYPE_RECIPIENT_MASK = 0x1F
    TYPE_RECIPIENT_DEVICE = 0x00
    TYPE_RECIPIENT_INTERFACE = 0x01
    TYPE_RECIPIENT_ENDPOINT = 0x02
    TYPE_RECIPIENT_OTHER = 0x03

    REQUEST_GET_STATUS = 0x00
    REQUEST_CLEAR_FEATURE = 0x01
    REQUEST_SET_FEATURE = 0x03
    REQUEST_SET_ADDRESS = 0x05
    REQUEST_GET_DESCRIPTOR = 0x06
    REQUEST_SET_DESCRIPTOR = 0x07
    REQUEST_GET_CONFIGURATION = 0x08
    REQUEST_SET_CONFIGURATION = 0x09
    # Interface
    REQUEST_SET_IDLE = 0x0A # class type
    REQUEST_GET_INTERFACE = 0x0A # standard type
    REQUEST_SET_INTERFACE = 0x11
    # Endpoint
    REQUEST_SYNCH_FRAME = 0x12

    DESCRIPTOR_MASK = 0xFF00
    INDEX_MASK = 0x00FF
    # Device?
    DESCRIPTOR_DEVICE = 0x0100
    DESCRIPTOR_CONFIGURATION = 0x0200
    DESCRIPTOR_STRING = 0x0300
    DESCRIPTOR_INTERFACE = 0x0400
    DESCRIPTOR_ENDPOINT = 0x0500
    DESCRIPTOR_DEVICE_QUALIFIER = 0x0600
    DESCRIPTOR_OTHER_SPEED_CONFIGURATION = 0x0700
    DESCRIPTOR_INTERFACE_POWER = 0x0800
    DESCRIPTOR_ON_THE_GO = 0x0900
    # Interface
    DESCRIPTOR_HID = 0x2200

    def __init__(self, data):
        self.bmRequestType, self.bRequest, self.wValue, self.wIndex, self.wLength = \
            self.struct.unpack(data[:self.struct.size])

    def direction(self):
        return self.bmRequestType & self.TYPE_DIR_MASK

    def get_desc_value(self):
        return self.wValue & self.DESCRIPTOR_MASK

    def get_desc_index(self):
        return self.wValue & self.INDEX_MASK

    def str_device_descriptor(self):
        match self.get_desc_value():
            case self.DESCRIPTOR_DEVICE:
                return "Device"
            case self.DESCRIPTOR_CONFIGURATION:
                return "Configuration"
            case self.DESCRIPTOR_STRING:
                return "String"
            case self.DESCRIPTOR_INTERFACE:
                return "Interface"
            case self.DESCRIPTOR_ENDPOINT:
                return "Endpoint"
            case self.DESCRIPTOR_DEVICE_QUALIFIER:
                return "Device-Qualifier"
            case self.DESCRIPTOR_OTHER_SPEED_CONFIGURATION:
                return "Other-Speed-Configuration"
            case self.DESCRIPTOR_INTERFACE_POWER:
                return "Interface-Power"
            case self.DESCRIPTOR_ON_THE_GO:
                return "On-The-Go"
        return "Unknown {self.get_desc_value()}"

    def __str__(self):
        setup_direction = "Host-To-Device"
        if self.direction() == self.TYPE_DIR_DEVICE_TO_HOST:
            setup_direction = "Device-To-Host"
        setup_type = "Standard"
        match self.bmRequestType & self.TYPE_MASK:
            case self.TYPE_CLASS:
                setup_type = "Class"
            case self.TYPE_VENDOR:
                setup_type = "Vendor"
            case self.TYPE_RESERVED:
                setup_type = "Reserved"
        setup_recipient = f"Unknown {self.bmRequestType & 0x0F}"
        setup_request = f"Unknown {self.bRequest}"
        match self.bmRequestType & self.TYPE_RECIPIENT_MASK:
            case self.TYPE_RECIPIENT_DEVICE:
                setup_recipient = "Device"
                match self.bRequest:
                    case self.REQUEST_GET_STATUS:
                        setup_request = "GET_STATUS"
                    case self.REQUEST_CLEAR_FEATURE:
                        setup_request = "CLEAR_FEATURE"
                    case self.REQUEST_SET_FEATURE:
                        setup_request = "SET_FEATURE"
                    case self.REQUEST_SET_ADDRESS:
                        setup_request = "SET_ADDRESS"
                    case self.REQUEST_GET_DESCRIPTOR:
                        setup_request = f"GET_DESCRIPTOR {self.str_device_descriptor()}"
                    case self.REQUEST_SET_DESCRIPTOR:
                        setup_request = "SET_DESCRIPTOR"
                    case self.REQUEST_GET_CONFIGURATION:
                        setup_request = "GET_CONFIGURATION"
                    case self.REQUEST_SET_CONFIGURATION:
                        setup_request = "SET_CONFIGURATION"
            case self.TYPE_RECIPIENT_INTERFACE:
                setup_recipient = "Interface"
                match self.bRequest:
                    case self.REQUEST_GET_STATUS:
                        setup_request = "GET_STATUS"
                    case self.REQUEST_CLEAR_FEATURE:
                        setup_request = "CLEAR_FEATURE"
                    case self.REQUEST_SET_FEATURE:
                        setup_request = "SET_FEATURE"
                    case self.REQUEST_GET_INTERFACE: # SET_IDLE
                        # not clear about this, getting conflicting info from different places
                        match self.bmRequestType & self.TYPE_MASK:
                            case self.TYPE_STANDARD:
                                setup_request = "GET_INTERFACE"
                            case self.TYPE_CLASS:
                                setup_request = "SET_IDLE"
                    case self.REQUEST_SET_INTERFACE:
                        setup_request = "SET_INTERFACE"
                    case self.REQUEST_GET_DESCRIPTOR:
                        match self.get_desc_value():
                            case self.DESCRIPTOR_HID:
                                setup_request = "GET_DESCRIPTOR HID Report"
                            case x:
                                setup_request = f"GET_DESCRIPTOR (INTERFACE) {x}"
            case self.TYPE_RECIPIENT_ENDPOINT:
                setup_recipient = "Endpoint"
                match self.bRequest:
                    case self.REQUEST_GET_STATUS:
                        setup_request = "GET_STATUS"
                    case self.REQUEST_CLEAR_FEATURE:
                        setup_request = "CLEAR_FEATURE"
                    case self.REQUEST_SET_FEATURE:
                        setup_request = "SET_FEATURE"
                    case self.REQUEST_SYNCH_FRAME:
                        setup_request = "SYNCH_FRAME"
            case self.TYPE_RECIPIENT_OTHER:
                setup_recipient = "Other"

        return f"Setup Direction: {setup_direction}, Setup Type: {setup_type}, " \
               f"Setup Recipient: {setup_recipient}, Setup Request: {setup_request}, " \
               f"Setup Value: {self.wValue}, Setup Index: {self.wIndex}, " \
               f"Setup Data Length: {self.wLength}"

    MATCH_REQUEST_GET_STATUS = (TYPE_DIR_DEVICE_TO_HOST | TYPE_STANDARD | TYPE_RECIPIENT_DEVICE, REQUEST_GET_STATUS)
    MATCH_REQUEST_CLEAR_FEATURE = (TYPE_DIR_HOST_TO_DEVICE | TYPE_STANDARD | TYPE_RECIPIENT_DEVICE, REQUEST_CLEAR_FEATURE)
    MATCH_REQUEST_SET_FEATURE = (TYPE_DIR_HOST_TO_DEVICE | TYPE_STANDARD | TYPE_RECIPIENT_DEVICE, REQUEST_SET_FEATURE)
    MATCH_REQUEST_SET_ADDRESS = (TYPE_DIR_HOST_TO_DEVICE | TYPE_STANDARD | TYPE_RECIPIENT_DEVICE, REQUEST_SET_ADDRESS)
    MATCH_REQUEST_GET_DESCRIPTOR = (TYPE_DIR_DEVICE_TO_HOST | TYPE_STANDARD | TYPE_RECIPIENT_DEVICE, REQUEST_GET_DESCRIPTOR)
    MATCH_REQUEST_SET_DESCRIPTOR = (TYPE_DIR_HOST_TO_DEVICE | TYPE_STANDARD | TYPE_RECIPIENT_DEVICE, REQUEST_SET_DESCRIPTOR)
    MATCH_REQUEST_GET_CONFIGURATION = (TYPE_DIR_DEVICE_TO_HOST | TYPE_STANDARD | TYPE_RECIPIENT_DEVICE, REQUEST_GET_CONFIGURATION)
    MATCH_REQUEST_SET_CONFIGURATION = (TYPE_DIR_HOST_TO_DEVICE | TYPE_STANDARD | TYPE_RECIPIENT_DEVICE, REQUEST_SET_CONFIGURATION)
    MATCH_REQUEST_SET_IDLE = (TYPE_DIR_HOST_TO_DEVICE | TYPE_CLASS | TYPE_RECIPIENT_INTERFACE, REQUEST_SET_IDLE)
    MATCH_REQUEST_GET_INTERFACE_DESCRIPTOR = (TYPE_DIR_DEVICE_TO_HOST | TYPE_STANDARD | TYPE_RECIPIENT_INTERFACE, REQUEST_GET_DESCRIPTOR)

    def decode(self):
        match (self.bmRequestType, self.bRequest):
            case self.MATCH_REQUEST_GET_STATUS:
                return "Setup Request Device Status"
            case self.MATCH_REQUEST_CLEAR_FEATURE:
                return f"Setup Request Clear Feature {self.wValue}"
            case self.MATCH_REQUEST_SET_FEATURE:
                return f"Setup Request Set Feature {self.wValue}"
            case self.MATCH_REQUEST_SET_ADDRESS:
                return f"Setup Request Set Address to {self.wValue}"
            case self.MATCH_REQUEST_GET_DESCRIPTOR:
                return f"Setup Request Get Descriptor {self.str_device_descriptor()}" \
                       f" {self.get_desc_index()} Language ID: {self.wIndex}" \
                       f" Requested Length: {self.wLength}"
            case self.MATCH_REQUEST_SET_DESCRIPTOR:
                return f"Setup Request Set Descriptor {self.str_device_descriptor()}" \
                       f" {self.get_desc_index()} Language ID: {self.wIndex}" \
                       f" Requested Length: {self.wLength}"
            case self.MATCH_REQUEST_GET_CONFIGURATION:
                return "Setup Request Get Configuration"
            case self.MATCH_REQUEST_SET_CONFIGURATION:
                return f"Setup Request Set Configuration {self.wValue}"
            case self.MATCH_REQUEST_SET_IDLE:
                return "Setup Request Set Idle"
            case self.MATCH_REQUEST_GET_INTERFACE_DESCRIPTOR:
                match self.get_desc_value():
                    case self.DESCRIPTOR_HID:
                        return f"Setup Request HID Report {self.wIndex}"
                    case x:
                        return f"Setup Request Get Interface Descriptor {x}" \
                               f" {self.get_desc_index()} Language ID: {self.wIndex}" \
                               f" Requested Length: {self.wLength}"
        return f"Setup Request Interpretation Unimplemented {self.bRequest:02X} {self.bmRequestType:02X}"

class ISOURB:
    error_count : int
    numdesc : int

    struct = struct.Struct("ii") # no idea how this works

    def __init__(self, data):
        self.error_count, self.numdesc = self.struct.unpack(data)

class URB:
    urb_id : int
    urb_type : int
    xfer_type : int
    epnum : int
    devnum : int
    busnum : int
    flag_setup : int
    flag_data : int
    ts_sec : int
    ts_nsec : int
    status : int
    length : int
    len_cap : int

    extra : (SetupURB | ISOURB)

    interval : int
    start_frame : int
    xfer_flags : int
    ndesc : int

    data : int

    struct_start = struct.Struct("LBBBBHBBliiII")
    struct_end = struct.Struct("iiII")

    URB_TYPE_COMPLETE = 67 # 'C"
    URB_TYPE_SUBMIT = 83 # 'S'

    XFER_TYPE_ISO = 0
    XFER_TYPE_INTERRUPT = 1
    XFER_TYPE_CONTROL = 2
    XFER_TYPE_BULK = 3

    ENDPOINT_DIR_MASK = 0x80
    ENDPOINT_MASK = 0x0F
    ENDPOINT_DIR_OUT = 0x00
    ENDPOINT_DIR_IN = 0x80

    FLAG_SETUP = 0
    FLAG_DATA_PRESENT = 61 #'='

    DESC_TYPE_DEVICE = 1
    DESC_TYPE_CONFIGURATION = 2
    DESC_TYPE_STRING = 3
    DESC_TYPE_INTERFACE = 4
    DESC_TYPE_ENDPOINT = 5

    SIZE = struct_start.size + SetupURB.struct.size + struct_end.size

    def direction(self):
        return self.epnum & self.ENDPOINT_DIR_MASK

    def endpoint(self):
        return self.epnum & self.ENDPOINT_MASK

    def str_endpoint(self):
        return str_endpoint(self.busnum, self.devnum, self.endpoint())

    def field_decode(self):
        urb_type_str = "Unknown"
        match self.urb_type:
            case self.URB_TYPE_COMPLETE:
                urb_type_str = "Complete"
            case self.URB_TYPE_SUBMIT:
                urb_type_str = "Submit"
        xfer_type_str = "Unknown"
        match self.xfer_type:
            case self.XFER_TYPE_ISO:
                xfer_type_str = "ISO"
            case self.XFER_TYPE_INTERRUPT:
                xfer_type_str = "Interrupt"
            case self.XFER_TYPE_CONTROL:
                xfer_type_str = "Control"
            case self.XFER_TYPE_BULK:
                xfer_type_str = "Bulk"
        direction = "Out/Host"
        if self.direction() == self.ENDPOINT_DIR_IN:
            direction = "In/Device"
        data_present = "No Data"
        if self.flag_data == self.FLAG_DATA_PRESENT:
            data_present = "Data Present"
        status_str = str(self.status)
        try:
            status_str = errno.errorcode[-self.status]
        except KeyError:
            if self.status == 0:
                status_str = "Success"

        return urb_type_str, xfer_type_str, direction, data_present, status_str

    def is_error(self):
        if -self.status in (0, errno.EINPROGRESS):
            return False
        return True

    def __init__(self, data, prev, verbose):
        self.rawdata = data
        # get beginning
        self.urb_id, self.urb_type, self.xfer_type, self.epnum, self.devnum, self.busnum, \
            self.flag_setup, self.flag_data, self.ts_sec, self.ts_nsec, self.status, \
            self.length, self.len_cap = self.struct_start.unpack(data[:self.struct_start.size])
        # get end
        self.interval, self.start_frame, self.xfer_flags, self.ndesc = \
            self.struct_end.unpack(data[self.struct_start.size+SetupURB.struct.size:self.struct_start.size+SetupURB.struct.size+self.struct_end.size])

        self.data = data[self.SIZE:]

        if self.is_error():
            return

        self.dev_map = DevMap(self.busnum, self.devnum)
        match self.xfer_type:
            case self.XFER_TYPE_CONTROL:
                if self.flag_setup == self.FLAG_SETUP:
                    # setup request
                    self.extra = SetupURB(data[self.struct_start.size:])
                else:
                    self.prev = prev
                    if prev.flag_setup == self.FLAG_SETUP:
                        match (prev.extra.bmRequestType, prev.extra.bRequest):
                            case SetupURB.MATCH_REQUEST_SET_CONFIGURATION:
                                devmap[self.dev_map].set_configuration(prev.extra.get_desc_index())
                            case SetupURB.MATCH_REQUEST_GET_DESCRIPTOR:
                                # setup with device descriptor request response
                                # maybe compare these values...
                                match prev.extra.get_desc_value():
                                    case SetupURB.DESCRIPTOR_DEVICE:
                                        self.new_dev = Device(self.data)
                                        # add new devices if they replace the old, and aren't a duplicate report
                                        if self.dev_map in devmap:
                                            if self.new_dev == devmap[self.dev_map]:
                                                if verbose:
                                                    print(f"{self.str_endpoint()} Ignoring same device in {self.dev_map.bus}.{self.dev_map.device}: {self.new_dev}")
                                            else:
                                                add_new_device(self.new_dev, self.dev_map)
                                                if verbose:
                                                    print(f"{self.str_endpoint()} Replacement in {self.dev_map.bus}.{self.dev_map.device}: {self.new_dev}")
                                        else:
                                            add_new_device(self.new_dev, self.dev_map)
                                    case SetupURB.DESCRIPTOR_CONFIGURATION:
                                        self.new_config = Configuration(self.data)
                                        devmap[self.dev_map].add_configuration(self.new_config)
                                    case SetupURB.DESCRIPTOR_STRING:
                                        index = prev.extra.get_desc_index()
                                        if index != 0:
                                            self.new_str = decode_string_desc(self.data)
                                            used = devmap[self.dev_map].set_string(index, self.new_str)
                                            if verbose and not used:
                                                print(f"{self.str_endpoint()} String \"{self.new_str}\" Not Used")
                            case SetupURB.MATCH_REQUEST_GET_INTERFACE_DESCRIPTOR:
                                match prev.extra.get_desc_value():
                                    case SetupURB.DESCRIPTOR_HID:
                                        devmap[self.dev_map].set_hid_report(prev.extra.get_desc_index(), self.data)

            case self.XFER_TYPE_INTERRUPT:
                self.result = devmap[self.dev_map].interrupt(self, prev)

    def __str__(self):
        urb_type_str, xfer_type_str, direction, data_present, status_str = self.field_decode()
        ret = f"URB ID: {self.urb_id:X}, URB Type: {urb_type_str}, Transfer Type: {xfer_type_str}, " \
              f"Direction/Subject: {direction}, Endpoint: {self.endpoint()}, " \
              f"Device: {self.devnum}, Bus: {self.busnum}, Setup Flag: {self.flag_setup}, " \
              f"Data Flag: {data_present}, Time: {self.ts_sec}, {self.ts_nsec}, " \
              f"Status: {status_str}, Requested Packet Length: {self.length}, " \
              f"Captured Length: {self.len_cap}, Interval: {self.interval}, " \
              f"Start Frame: {self.start_frame}, Transfer Flags: {self.xfer_flags}, " \
              f"ISO Descriptors: {self.ndesc}"
        if self.flag_setup == self.FLAG_SETUP:
            ret += f", {self.extra}"
        if len(self.data) > 0:
            ret += f"\n{str_hex(self.data)}"
        return ret

    def decode(self):
        if self.is_error():
            return f"{self.str_endpoint()} Error {-self.status} {errno.errorcode[-self.status]}"

        match self.xfer_type:
            case self.XFER_TYPE_CONTROL:
                if self.flag_setup == self.FLAG_SETUP:
                    # setup request
                    return f"{self.str_endpoint()} {self.extra.decode()}"
                else:
                    prev = self.prev
                    if prev.flag_setup == self.FLAG_SETUP:
                        # setup response
                        match (prev.extra.bmRequestType, prev.extra.bRequest):
                            case SetupURB.MATCH_REQUEST_SET_CONFIGURATION:
                                return f"{self.str_endpoint()} Set Configuration Response"
                            case SetupURB.MATCH_REQUEST_SET_IDLE:
                                return f"{self.str_endpoint()} Set Idle Response"
                            case SetupURB.MATCH_REQUEST_GET_DESCRIPTOR:
                                if len(self.data) == 0:
                                    return f"{self.str_endpoint()} Response with No Data"
                                else:
                                    match prev.extra.get_desc_value():
                                        case SetupURB.DESCRIPTOR_DEVICE:
                                            return f"{self.str_endpoint()} {self.new_dev}"
                                        case SetupURB.DESCRIPTOR_CONFIGURATION:
                                            return f"{self.str_endpoint()} {self.new_config}"
                                        case SetupURB.DESCRIPTOR_STRING:
                                            index = prev.extra.get_desc_index()
                                            if index == 0:
                                                ret = f"{self.str_endpoint()} String Languages Record:"
                                                for language in decode_language_list(self.data):
                                                    ret += f" {language}"
                                                return ret
                                            return f"{self.str_endpoint()} String Response: \"{self.new_str}\""
                            case SetupURB.MATCH_REQUEST_GET_INTERFACE_DESCRIPTOR:
                                match prev.extra.get_desc_value():
                                    case SetupURB.DESCRIPTOR_HID:
                                        return f"{self.str_endpoint()} HID Report Response  " \
                                               f"{devmap[self.dev_map].get_hid_report(prev.extra.get_desc_index())}"

                return f"{self.str_endpoint()} Unsupported Control Response"
            case self.XFER_TYPE_INTERRUPT:
                return f"{self.str_endpoint()} {self.result}"
        return f"{self.str_endpoint()} Interpretation Unimplemented"

def decode(infile, verbose, count):
    scanner = pcapng.FileScanner(infile)
    urb = None
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
                urb = URB(block.packet_data, urb, verbose)
                if verbose:
                    print(urb)
                print(urb.decode())
            except Exception as e:
                print(str_hex(block.packet_data))
                raise e
        elif isinstance(block, pcapng.blocks.InterfaceStatistics):
            pass
        else:
            print("Unhandled block type")
            print(block)
            break
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
            decode(infile, verbose, 100)
