from dataclasses import dataclass
import struct
import errno
import array

from .util import chrbyte, strbcd, str_hex, SHIFT_MASKS_LOW, SHIFT_MASKS_HIGH, BIT_MASKS, MICROSECOND

class UninterpretableDataException(Exception):
    pass

def get_better_string(orig, new):
    # if the new string is a truncated version of the original
    # just keep the original
    if orig.startswith(new):
        return False, orig
    # otherwise, apply the new string
    return True, new

@dataclass(frozen=True, eq=True)
class DevMap:
    bus : int
    device : int

class HIDCollection:
    collection_id : int # not part of the binary format
    flag : int
    usage : int

    def __init__(self, collection_id, flag=-1, usage=0):
        self.collection_id = collection_id
        self.flag = flag
        self.usage = usage
        self.items = []

    def append(self, item):
        self.items.append(item)

    def __str__(self):
        ret = "("
        if self.flag >= 0:
            ret = f"{HID.str_collection_type(self.flag)}/{HID.str_usage(self.usage)}("
        for num, item in enumerate(self.items):
            ret += str(item)
            if num < len(self.items)-1:
                ret += ", "
        ret += ")"
        return ret

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)

    def __eq__(self, other):
        return self.collection_id == other.collection_id

    def __contains__(self, item):
        for report in self.items:
            if isinstance(report, HIDCollection) and report.collection_id == item.collection_id:
                return True
        return False

    def __getitem__(self, item):
        for report in self.items:
            if isinstance(report, HIDCollection) and report.collection_id == item:
                return report
        raise IndexError("No collection with id {item} in this collection!")

    def get_size(self):
        size = 0
        for report in self:
            if isinstance(report, HIDCollection):
                size += report.get_size()
            else:
                size += report.size * report.count
        return size

@dataclass
class HIDIOItem:
    direction : int
    report_id : int
    flags : int
    usage : int
    size : int
    count : int

    def __str__(self):
        direction = "Input"
        if self.direction == Endpoint.ADDRESS_DIR_OUT:
            direction = "Output"
        flag_str = "Padding"
        usage_str = ""
        if not self.flags & HID.ITEM_MAIN_FLAG_CONSTANT:
            flag_str = "Data"
            if isinstance(self.usage, range):
                usage_str = f"[{self.usage.start}-{self.usage.stop}]"
            else:
                usage_str = "["
                for num, usage in enumerate(self.usage):
                    usage_str += HID.str_usage(usage)
                    if num < len(self.usage)-1:
                        usage_str += ", "
                usage_str += "]"
        return f"{direction} ID:{self.report_id} {flag_str}{usage_str} {self.size}bit x{self.count}"

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
    ITEM_USAGE_GENERIC_DESKTOP_KEYBOARD = 0x0006
    ITEM_USAGE_GENERIC_DESKTOP_X_AXIS = 0x0030
    ITEM_USAGE_GENERIC_DESKTOP_Y_AXIS = 0x0031
    ITEM_USAGE_GENERIC_DESKTOP_WHEEL = 0x0038
    ITEM_USAGE_GENERIC_SYSTEM_CONTROL = 0x0080
    ITEM_USAGE_GENERIC_SYSTEM_POWER_DOWN = 0x0081
    ITEM_USAGE_GENERIC_SYSTEM_SLEEP = 0x0082
    ITEM_USAGE_GENERIC_SYSTEM_WAKE_UP = 0x0083

    ITEM_USAGE_CONSUMER_CONTROL = 0x0001
    ITEM_USAGE_CONSUMER_EJECT = 0x00B8
    ITEM_USAGE_CONSUMER_PAN = 0x0238

    ITEM_USAGE_BARCODE_BADGE_READER = 0x0001
    ITEM_USAGE_BARCODE_SCANNER = 0x0002
    ITEM_USAGE_BARCODE_DUMB_SCANNER = 0x0003

    # I guess python really does suck
    # specify endianness to ignore alignment?
    struct = struct.Struct("<BBHBBBH")

    def str_main_flags(value, input_item):
        if value & HID.ITEM_MAIN_FLAG_CONSTANT:
            ret = "Constant"
        else:
            ret = "Data"
        if value & HID.ITEM_MAIN_FLAG_VARIABLE:
            ret += ":Variable"
        else:
            ret += ":Array"
        if value & HID.ITEM_MAIN_FLAG_RELATIVE:
            ret += ":Relative"
        else:
            ret += ":Absolute"
        if value & HID.ITEM_MAIN_FLAG_WRAP:
            ret += ":Wrap"
        else:
            ret += ":No-Wrap"
        if value & HID.ITEM_MAIN_FLAG_NON_LINEAR:
            ret += ":Non-Linear"
        else:
            ret += ":Linear"
        if value & HID.ITEM_MAIN_FLAG_NO_PREFERRED:
            ret += ":No-Preferred-State"
        else:
            ret += ":Preferred-State"
        if value & HID.ITEM_MAIN_FLAG_NULL_STATE:
            ret += ":Null-State"
        else:
            ret += ":No-Null-State"
        if not input_item:
            if value & HID.ITEM_MAIN_FLAG_VOLATILE:
                ret += ":Volatile"
            else:
                ret += ":Non-Volatile"
        if value & HID.ITEM_MAIN_FLAG_BUFFERED_BYTES:
            ret += ":Buffered-Bytes"
        else:
            ret += ":Bit-Field"
        return ret

    def str_collection_type(value):
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
    def data_uint(data, high_16=False):
        value = 0
        for pos in range(len(data)):
            value |= data[pos] << (pos * 8)
        if high_16 and value <= 0xFFFF:
            value <<= 16
        return value

    def data_sint(data):
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
                    case 0:
                        pass
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_POINTER:
                        ret += "/Pointer"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_MOUSE:
                        ret += "/Mouse"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_KEYBOARD:
                        ret += "/Keyboard"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_X_AXIS:
                        ret += "/X-Axis"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_Y_AXIS:
                        ret += "/Y-Axis"
                    case HID.ITEM_USAGE_GENERIC_DESKTOP_WHEEL:
                        ret += "/Wheel"
                    case HID.ITEM_USAGE_GENERIC_SYSTEM_CONTROL:
                        ret += "/System-Control"
                    case HID.ITEM_USAGE_GENERIC_SYSTEM_POWER_DOWN:
                        ret += "/Power-Down"
                    case HID.ITEM_USAGE_GENERIC_SYSTEM_SLEEP:
                        ret += "/Sleep"
                    case HID.ITEM_USAGE_GENERIC_SYSTEM_WAKE_UP:
                        ret += "/Wake-Up"
                    case _:
                        ret += "/Unknown"
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
                    case 0:
                        pass
                    case HID.ITEM_USAGE_CONSUMER_CONTROL:
                        ret += "/Control"
                    case HID.ITEM_USAGE_CONSUMER_EJECT:
                        ret += "/Eject"
                    case HID.ITEM_USAGE_CONSUMER_PAN:
                        ret += "/Application-Control-Pan"
                    case _:
                        ret += "/Unknown"
                return ret
            case HID.ITEM_USAGE_PAGE_UNICODE:
                return "Unicode"
            case HID.ITEM_USAGE_PAGE_BARCODE_SCANNER:
                ret = "Barcode-Scanner"
                match value & HID.ITEM_USAGE_MASK:
                    case 0:
                        pass
                    case HID.ITEM_USAGE_BARCODE_BADGE_READER:
                        ret += "/Badge-Reader"
                    case HID.ITEM_USAGE_BARCODE_SCANNER:
                        ret += "/Scanner"
                    case HID.ITEM_USAGE_BARCODE_DUMB_SCANNER:
                        ret += "/Dumb-Scanner"
                    case _:
                        ret += "/Unknown"
                return ret
        return "Unknown"

    def decode_desc(self, data):
        usage_page = 0
        logical_minimum = 0
        logical_maximum = 0
        physical_minimum = 0
        physical_maximum = 0
        unit_exponent = 0
        unit = 0
        report_size = 0
        report_id = 0
        report_count = 0

        usage_list = []
        usage_minimum = 0
        usage_maximum = 0
        designator_list = []
        designator_minimum = 0
        designator_maximum = 0
        string_list = []
        string_minimum = 0
        string_maximum = 0

        stack = []

        collections = [self.descriptors]

        collection_id = 1 # the "root" is already 0
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
                type_str = "Unknown"
                tag_str = "Unknown"
                data_str = ""
                match data[pos] & self.ITEM_TYPE_MASK:
                    case self.ITEM_TYPE_MAIN:
                        type_str = "Main"
                        match data[pos] & self.ITEM_TAG_MASK:
                            case self.ITEM_MAIN_INPUT:
                                tag_str = "Input"
                                flags = HID.data_uint(data[pos+1:pos+1+size])
                                # not 100% on this
                                collection_usage = usage_list
                                if len(usage_list) == 0:
                                    collection_usage = range(usage_minimum, usage_maximum)
                                collections[-1].append(HIDIOItem(Endpoint.ADDRESS_DIR_IN, report_id, flags,
                                                                 collection_usage, report_size, report_count))
                                # not 100% on this either but "locals" seem to reset?
                                usage_list = []
                                usage_minimum = 0
                                usage_maximum = 0
                                designator_list = []
                                designator_minimum = 0
                                designator_maximum = 0
                                string_list = []
                                string_minimum = 0
                                string_maximum = 0
                                data_str = HID.str_main_flags(flags, True)
                            case self.ITEM_MAIN_OUTPUT:
                                tag_str = "Output"
                                flags = HID.data_uint(data[pos+1:pos+1+size])
                                collection_usage = usage_list
                                if len(usage_list) == 0:
                                    collection_usage = range(usage_minimum, usage_maximum)
                                collections[-1].append(HIDIOItem(Endpoint.ADDRESS_DIR_OUT, report_id, flags,
                                                                 collection_usage, report_size, report_count))
                                usage_list = []
                                usage_minimum = 0
                                usage_maximum = 0
                                designator_list = []
                                designator_minimum = 0
                                designator_maximum = 0
                                string_list = []
                                string_minimum = 0
                                string_maximum = 0
                                data_str = HID.str_main_flags(flags, False)
                            case self.ITEM_MAIN_FEATURE:
                                tag_str = "Feature"
                                # not implemented
                                flags = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = HID.str_main_flags(flags, False)
                            case self.ITEM_MAIN_COLLECTION:
                                tag_str = "Collection"
                                flags = HID.data_uint(data[pos+1:pos+1+size])
                                collections.append(HIDCollection(collection_id, flags, usage))
                                collection_id += 1
                                collections[-2].append(collections[-1])
                                usage_list = []
                                usage_minimum = 0
                                usage_maximum = 0
                                designator_list = []
                                designator_minimum = 0
                                designator_maximum = 0
                                string_list = []
                                string_minimum = 0
                                string_maximum = 0
                                data_str = HID.str_collection_type(flags)
                                pad_change = 1
                            case self.ITEM_MAIN_END_COLLECTION:
                                tag_str = "End-Collection"
                                collections = collections[:-1]
                                pad_change = -1
                    case self.ITEM_TYPE_GLOBAL:
                        type_str = "Global"
                        match data[pos] & self.ITEM_TAG_MASK:
                            case self.ITEM_GLOBAL_USAGE_PAGE:
                                tag_str = "Usage-Page"
                                usage_page = HID.data_uint(data[pos+1:pos+1+size], True)
                                data_str = f"{usage_page:08X} {HID.str_usage(usage_page)}"
                                # later usage values will overwrite at least the lower 16 bits
                                usage_page &= self.ITEM_USAGE_PAGE_MASK
                            case self.ITEM_GLOBAL_LOGICAL_MINIMUM:
                                tag_str = "Logical-Minimum"
                                logical_minimum = HID.data_sint(data[pos+1:pos+1+size])
                                data_str = logical_minimum
                            case self.ITEM_GLOBAL_LOGICAL_MAXIMUM:
                                tag_str = "Logical-Maximum"
                                logical_maximum = HID.data_sint(data[pos+1:pos+1+size])
                                data_str = logical_maximum
                            case self.ITEM_GLOBAL_PHYSICAL_MINIMUM:
                                tag_str = "Physical-Minimum"
                                physical_minimum = HID.data_sint(data[pos+1:pos+1+size])
                                data_str = physical_minimum
                            case self.ITEM_GLOBAL_PHYSICAL_MAXIMUM:
                                tag_str = "Physical-Maximum"
                                physical_maximum = HID.data_sint(data[pos+1:pos+1+size])
                                data_str = physical_maximum
                            case self.ITEM_GLOBAL_UNIT_EXPONENT:
                                tag_str = "Unit-Exponent"
                                unit_exponent = HID.data_sint(data[pos+1:pos+1+size])
                                data_str = f"*10^{unit_exponent}"
                            case self.ITEM_GLOBAL_UNIT:
                                tag_str = "Unit"
                                unit = HID.data_sint(data[pos+1:pos+1+size])
                                # not likely going to try...
                                data_str = f"{unit:08X}"
                            case self.ITEM_GLOBAL_REPORT_SIZE:
                                tag_str = "Report-Size"
                                report_size = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = report_size
                            case self.ITEM_GLOBAL_REPORT_ID:
                                tag_str = "Report-ID"
                                report_id = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = report_id
                            case self.ITEM_GLOBAL_REPORT_COUNT:
                                tag_str = "Report-Count"
                                report_count = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = report_count
                            case self.ITEM_GLOBAL_PUSH:
                                # not confident this is how these work!
                                tag_str = "Push"
                                stack.append(usage_page, logical_minimum, logical_maximum,
                                             physical_minimum, physical_maximum, unit_exponent,
                                             unit, report_size, report_id, report_count)
                            case self.ITEM_GLOBAL_POP:
                                tag_str = "Pop"
                                usage_page, logical_minimum, logical_maximum, physical_minimum, \
                                    physical_maximum, unit_exponent, unit, report_size, \
                                    report_id, report_count = stack.pop()
                    case self.ITEM_TYPE_LOCAL:
                        type_str = "Local"
                        match data[pos] & self.ITEM_TAG_MASK:
                            case self.ITEM_LOCAL_USAGE:
                                tag_str = "Usage"
                                usage = HID.data_uint(data[pos+1:pos+1+size])
                                if usage <= self.ITEM_USAGE_MASK:
                                    usage |= usage_page
                                usage_list.append(usage)
                                data_str = f"{usage:08X} {HID.str_usage(usage)}"
                            case self.ITEM_LOCAL_USAGE_MINIMUM:
                                tag_str = "Usage-Minimum"
                                usage_minimum = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = usage_minimum
                            case self.ITEM_LOCAL_USAGE_MAXIMUM:
                                tag_str = "Usage-Maximum"
                                usage_maximum = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = usage_maximum
                            case self.ITEM_LOCAL_DESIGNATOR_INDEX:
                                # not implemented (no examples)
                                tag_str = "Designator-Index"
                                designator_index = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = designator_index
                            case self.ITEM_LOCAL_DESIGNATOR_MINIMUM:
                                tag_str = "Designator-Minimum"
                                designator_minimum = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = designator_minimum
                            case self.ITEM_LOCAL_DESIGNATOR_MAXIMUM:
                                tag_str = "Designator-Maximum"
                                designator_maximum = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = designator_maximum
                            case self.ITEM_LOCAL_STRING_INDEX:
                                # same
                                tag_str = "String-Index"
                                string_index = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = string_index
                            case self.ITEM_LOCAL_STRING_MINIMUM:
                                tag_str = "String-Minimum"
                                string_minimum = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = string_minimum
                            case self.ITEM_LOCAL_STRING_MAXIMUM:
                                tag_str = "String-Maximum"
                                string_maximum = HID.data_uint(data[pos+1:pos+1+size])
                                data_str = string_maximum
                            case self.ITEM_LOCAL_DELIMITER:
                                # for now not implemented (not clear on how it works)
                                tag_str = "Delimiter"
                                data_str = "Closed-Set"
                                if HID.data_uint(data[pos+1:pos+1+size]):
                                    data_str = "Open-Set"
                    case self.ITEM_TYPE_RESERVED:
                        type_str = "Reserved"
                if pad_change < 0:
                    padding = padding[:-1]
                self.desc_str += f"\n{padding}{type_str}/{tag_str} {data_str}"
                if pad_change > 0:
                    padding += " "
                pos += size + self.ITEM_SHORT_HDR_SIZE

    def value_bits_from_data(data, bytepos, bitpos, bits):
        value = array.array('B')
        byte = data[bytepos]

        if bitpos > 0:
            byte &= SHIFT_MASKS_LOW[bitpos]
            byte <<= bitpos

            for i in range(bits // 8):
                byte2 = data[bytepos+1+i]
                byte2 >>= 8-bitpos

                value.append(byte | byte2)

                byte = data[bytepos+1+i]
                byte &= SHIFT_MASKS_LOW[bitpos]
                byte <<= bitpos

            if (bitpos + bits) % 8 > 0:
                byte2 = data[bytepos+(bits // 8)]
                byte2 >>= 8-bitpos
            else:
                byte2 = 0

            value.append((byte | byte2) & SHIFT_MASKS_HIGH[(bitpos + bits) % 8])
        else:
            for i in range(bits // 8):
                value.append(data[bytepos+i])

            if bits % 8 > 0:
                byte = data[bytepos+(bits // 8)]
                byte &= SHIFT_MASKS_HIGH[bits % 8]

                value.append(byte)

        return value

    def process_collection(data, report_id, direction, collection, bytepos=0, bitpos=0):
        ret = "("
        for num, report in enumerate(collection):
            if isinstance(report, HIDCollection):
                new_str = HID.process_collection(data, report_id, direction, report, bytepos, bitpos)
                if new_str is not None:
                    ret += new_str
                    if num < len(collection) - 1:
                        ret += " "
            else:
                if report.direction == direction and report.report_id == report_id:
                    if not report.flags & HID.ITEM_MAIN_FLAG_CONSTANT:
                        ret += "["
                        for countnum, i in enumerate(range(report.count)):
                            value = HID.value_bits_from_data(data, bytepos, bitpos, report.size)
                            if report.size % 8 == 0:
                                for bytenum, byte in enumerate(value):
                                    ret += f"{byte:02X}"
                                    if bytenum < len(value) - 1:
                                        ret += " "
                            else:
                                for bytenum, byte in enumerate(value):
                                    for bit in range(8):
                                        if bytenum * 8 + bit >= report.size:
                                            break
                                        if byte & BIT_MASKS[bit]:
                                            ret += "#"
                                        else:
                                            ret += "."
                            if countnum < report.count - 1:
                                ret += " "
                            bytepos += report.size // 8
                            bitpos += report.size % 8
                            while bitpos >= 8:
                                bytepos += 1
                                bitpos -= 8
                        ret += "]"
                    else:
                        bytepos += report.size * report.count // 8
                        bitpos += report.size * report.count % 8
                        while bitpos >= 8:
                            bytepos += 1
                            bitpos -= 8
        if len(ret) == 1:
            return None
        ret += ")"
        return ret

    def decode_interrupt(self, report_id, direction, data):
        try:
            ret = HID.process_collection(data, report_id, direction, self.descriptors)
        except IndexError:
            return f"Malformed packet!"
        if ret is not None:
            dir_str = "In"
            if direction == Endpoint.ADDRESS_DIR_OUT:
                dir_str = "Out"
            return f"HID Report {dir_str} {report_id}: ({ret})"
        else:
            return f"Couldn't extract data from HID report!"

    def do_get_reports(reports, collections, direction):
        for report in collections[-1]:
            if isinstance(report, HIDCollection):
                # add the collection to the stack and process any collections or reports
                collections.append(report)
                HID.do_get_reports(reports, collections, direction)
                # pop it back off
                collections = collections[:-1]
            else:
                if not report.flags & HID.ITEM_MAIN_FLAG_CONSTANT and \
                   report.direction == direction:
                    # if this report hasn't been seen yet, add it to the map
                    if report.report_id not in reports:
                        reports[report.report_id] = HIDCollection(0)
                    # make sure there's a path to this report
                    # and make report_collection the collection to add the report to
                    report_collection = reports[report.report_id]
                    for collection in collections[1:]:
                        try:
                            report_collection = report_collection[collection.collection_id]
                        except IndexError:
                            report_collection.append(HIDCollection(collection.collection_id, collection.flag, collection.usage))
                            report_collection = report_collection[collection.collection_id]
                    # add the applicable report
                    report_collection.append(report)

    def get_reports(self, direction):
        reports = {}
        collections = [self.descriptors]

        HID.do_get_reports(reports, collections, direction)

        return reports

    def __init__(self, data=None):
        if data is not None:
            length, desc, self.hid, self.country_code, self.num_descriptor, self.descriptor_type, \
                self.descriptor_length = self.struct.unpack(data[:self.struct.size])
        else:
            self.hid = 0
            self.country_code = 0
            self.num_descriptor = 0
            self.descriptor_type = 0
            self.descriptor_length = 0
        self.desc_str = ""
        self.descriptors = HIDCollection(0)

    def __str__(self):
        return f"HID  ID: {strbcd(self.hid)} Country Code: {self.country_code}" \
               f" Descriptors: {self.num_descriptor} Type: {self.descriptor_type}" \
               f" Descriptor Length: {self.descriptor_length}{self.desc_str}\n" \
               f" Structure: {self.descriptors}"

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

    def interrupt(self, endpoint, data):
        if self.interface_class == self.CLASS_HID:
            return self.hid.decode_interrupt(data[0], self.endpoints[endpoint].get_direction(), data[1:])
        return None

    def get_endpoints(self):
        return self.endpoints.keys()

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
        self.endpoint_map = {}
        if len(data) >= self.total_length - URB.SIZE:
            # decode following interfaces
            pos = self.struct.size
            for i in range(self.num_interfaces):
                interface = Interface(data[pos:])
                self.interfaces[interface.interface_id] = interface
                pos += interface.get_size()
                for endpoint in interface.get_endpoints():
                    self.endpoint_map[endpoint] = interface
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

    def interrupt(self, endpoint, data):
        return self.endpoint_map[endpoint].interrupt(endpoint, data)

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
            ret = self.configurations[self.configuration].interrupt(urb.endpoint(), urb.data)
            if ret is None:
                return InterruptUnknown("In", urb.data)
            else:
                return ret
        # Out
        if len(urb.data) == 0:
            if prev.xfer_type == URB.XFER_TYPE_INTERRUPT and \
               prev.direction() == URB.ENDPOINT_DIR_OUT and \
               urb.urb_type == URB.URB_TYPE_COMPLETE:
                return InterruptAcknowledge("Out")
            else:
                return InterruptNoData("Out")
        ret = self.configurations[self.configuration].interrupt(urb.endpoint(), urb.data)
        if ret is None:
            return InterruptUnknown("Out", urb.data)
        else:
            return ret

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
        return f"Unknown {self.get_desc_value()}"

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
    ts_usec : int
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
        return f"{self.busnum}.{self.devnum}.{self.endpoint()}"

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

    def decode_string_desc(data):
        # don't need the length nor desc type
        return data[2:].decode('utf-16')

    def decode_language_list(data):
        languages = []
        # don't need the length nor desc type
        for i in range(2, len(data), 2):
            languages.append(data[i] | (data[i+1] << 8))
        return languages

    def __init__(self, devmap, data, prev, verbose):
        self.prev = None
        self.extra = None
        self.data = None
        self.decode_str = None
        self.devmap = devmap
        self.rawdata = data
        # get beginning
        self.urb_id, self.urb_type, self.xfer_type, self.epnum, self.devnum, self.busnum, \
            self.flag_setup, self.flag_data, self.ts_sec, self.ts_usec, self.status, \
            self.length, self.len_cap = self.struct_start.unpack(data[:self.struct_start.size])
        # get end
        self.interval, self.start_frame, self.xfer_flags, self.ndesc = \
            self.struct_end.unpack(data[self.struct_start.size+SetupURB.struct.size:self.struct_start.size+SetupURB.struct.size+self.struct_end.size])

        self.dev_map = DevMap(self.busnum, self.devnum)

        self.state = False

        if self.is_error():
            if -self.status == errno.ENOENT:
                # device no longer exists
                del devmap[self.dev_map]
                self.state = self.dev_map
            return

        if self.dev_map not in devmap:
            # device doesn't exist
            if self.xfer_type == self.XFER_TYPE_CONTROL:
                if self.flag_setup == self.FLAG_SETUP:
                    # check to see if it's a device descriptor request
                    setup_urb = SetupURB(data[self.struct_start.size:])
                    if not ((setup_urb.bmRequestType, setup_urb.bRequest) == SetupURB.MATCH_REQUEST_GET_DESCRIPTOR and \
                            setup_urb.get_desc_value() == SetupURB.DESCRIPTOR_DEVICE):
                        return
                else:
                    # check to see if it's a device descriptor response
                    if prev.flag_setup == self.FLAG_SETUP:
                        if prev.extra is None or \
                           not ((prev.extra.bmRequestType, prev.extra.bRequest) == SetupURB.MATCH_REQUEST_GET_DESCRIPTOR and \
                                prev.extra.get_desc_value() == SetupURB.DESCRIPTOR_DEVICE):
                            return
            else:
                return

        self.data = data[self.SIZE:]

        match self.xfer_type:
            case self.XFER_TYPE_CONTROL:
                self.state = True
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
                                        # Try to find an identical device this may map to
                                        found = None
                                        for device in devmap.keys():
                                            if self.new_dev == devmap[device]:
                                                found = device
                                                break

                                        if found is None:
                                            # if not found, just add it as usual
                                            devmap[self.dev_map] = self.new_dev
                                        else:
                                            # if one was found, alias it to the old
                                            devmap[self.dev_map] = devmap[found]
                                    case SetupURB.DESCRIPTOR_CONFIGURATION:
                                        self.new_config = Configuration(self.data)
                                        devmap[self.dev_map].add_configuration(self.new_config)
                                    case SetupURB.DESCRIPTOR_STRING:
                                        index = prev.extra.get_desc_index()
                                        if index != 0:
                                            self.new_str = URB.decode_string_desc(self.data)
                                            used = devmap[self.dev_map].set_string(index, self.new_str)
                                            if verbose and not used:
                                                print(f"{self.str_endpoint()} String \"{self.new_str}\" Not Used")
                            case SetupURB.MATCH_REQUEST_GET_INTERFACE_DESCRIPTOR:
                                match prev.extra.get_desc_value():
                                    case SetupURB.DESCRIPTOR_HID:
                                        devmap[self.dev_map].set_hid_report(prev.extra.wIndex, self.data)
            case self.XFER_TYPE_INTERRUPT:
                self.result = devmap[self.dev_map].interrupt(self, prev)

    def __str__(self):
        urb_type_str, xfer_type_str, direction, data_present, status_str = self.field_decode()
        ret = f"URB ID: {self.urb_id:X}, URB Type: {urb_type_str}, Transfer Type: {xfer_type_str}, " \
              f"Direction/Subject: {direction}, Endpoint: {self.endpoint()}, " \
              f"Device: {self.devnum}, Bus: {self.busnum}, Setup Flag: {self.flag_setup}, " \
              f"Data Flag: {data_present}, Time: {self.ts_sec}, {self.ts_usec}, " \
              f"Status: {status_str}, Requested Packet Length: {self.length}, " \
              f"Captured Length: {self.len_cap}, Interval: {self.interval}, " \
              f"Start Frame: {self.start_frame}, Transfer Flags: {self.xfer_flags}, " \
              f"ISO Descriptors: {self.ndesc}"
        if self.flag_setup == self.FLAG_SETUP:
            ret += f", {self.extra}"
        if self.data is not None and len(self.data) > 0:
            ret += f"\n{str_hex(self.data)}"
        return ret

    def decode(self):
        if self.decode_str is None:
            if self.is_error():
                if -self.status == errno.ENOENT:
                    self.decode_str = f"{self.str_endpoint()} Error device reported not found!  Removing."
                else:
                    self.decode_str = f"{self.str_endpoint()} Error {-self.status} {errno.errorcode[-self.status]}"
            if self.decode_str is not None:
                return self.decode_str

            if self.dev_map not in self.devmap:
                # device doesn't exist
                if self.xfer_type == self.XFER_TYPE_CONTROL:
                    if self.flag_setup == self.FLAG_SETUP:
                        # check to see if it's a device descriptor request
                        setup_urb = SetupURB(self.rawdata[self.struct_start.size:])
                        if not ((setup_urb.bmRequestType, setup_urb.bRequest) == SetupURB.MATCH_REQUEST_GET_DESCRIPTOR and \
                                setup_urb.get_desc_value() == SetupURB.DESCRIPTOR_DEVICE):
                            self.decode_str = f"{self.str_endpoint()} Device not found and not a device descriptor!"
                    else:
                        if self.prev is None:
                            self.decode_str = f"{self.str_endpoint()} Device not found and not a device descriptor!"
                else:
                    self.decode_str = f"{self.str_endpoint()} Device not found and not a device descriptor!"
            if self.decode_str is not None:
                return self.decode_str

            match self.xfer_type:
                case self.XFER_TYPE_CONTROL:
                    if self.flag_setup == self.FLAG_SETUP:
                        # setup request
                        self.decode_str = f"{self.str_endpoint()} {self.extra.decode()}"
                    else:
                        prev = self.prev
                        if prev.flag_setup == self.FLAG_SETUP:
                            # setup response
                            match (prev.extra.bmRequestType, prev.extra.bRequest):
                                case SetupURB.MATCH_REQUEST_SET_CONFIGURATION:
                                    self.decode_str = f"{self.str_endpoint()} Set Configuration Response"
                                case SetupURB.MATCH_REQUEST_SET_IDLE:
                                    self.decode_str = f"{self.str_endpoint()} Set Idle Response"
                                case SetupURB.MATCH_REQUEST_GET_DESCRIPTOR:
                                    if len(self.data) == 0:
                                        self.decode_str = f"{self.str_endpoint()} Response with No Data"
                                    else:
                                        match prev.extra.get_desc_value():
                                            case SetupURB.DESCRIPTOR_DEVICE:
                                                self.decode_str = f"{self.str_endpoint()} {self.new_dev}"
                                            case SetupURB.DESCRIPTOR_CONFIGURATION:
                                                self.decode_str = f"{self.str_endpoint()} {self.new_config}"
                                            case SetupURB.DESCRIPTOR_STRING:
                                                index = prev.extra.get_desc_index()
                                                if index == 0:
                                                    self.decode_str = f"{self.str_endpoint()} String Languages Record:"
                                                    for language in URB.decode_language_list(self.data):
                                                        self.decode_str += f" {language}"
                                                else:
                                                    self.decode_str = f"{self.str_endpoint()} String Response: \"{self.new_str}\""
                                case SetupURB.MATCH_REQUEST_GET_INTERFACE_DESCRIPTOR:
                                    match prev.extra.get_desc_value():
                                        case SetupURB.DESCRIPTOR_HID:
                                            self.decode_str = f"{self.str_endpoint()} HID Report Response  " \
                                                              f"{self.devmap[self.dev_map].get_hid_report(prev.extra.wIndex)}"
                    if self.decode_str is None:
                        self.decode_str = f"{self.str_endpoint()} Unsupported Control Response"
                case self.XFER_TYPE_INTERRUPT:
                    self.decode_str = f"{self.str_endpoint()} {self.result}"
            if self.decode_str is None:
                self.decode_str = f"{self.str_endpoint()} Interpretation Unimplemented"
        return self.decode_str

    def __eq__(self, other):
        if self.decode() == other.decode():
            return True
        return False

class USBContext:
    def __init__(self, verbose=False):
        self.verbose = verbose
        # present view of devices at any moment
        self.devmap = {}
        self.prev = None
        self.start_sec = 0
        self.start_usec = 0
        self.state_urbs = []

    def parse_urb(self, data):
        self.prev = URB(self.devmap, data, self.prev, self.verbose)

        if isinstance(self.prev.state, DevMap):
            # lost device sets state to the DevMap for the device that was lost
            # delete any state URBs with this devmap
            delete_urbs = []
            for urb in self.state_urbs:
                if urb.dev_map == self.prev.state:
                    delete_urbs.append(urb)
            for urb in delete_urbs:
                self.state_urbs.remove(urb)
        elif self.prev.state:
            # save URBs relevant to state
            self.state_urbs.append(self.prev)

        if self.start_sec == 0:
            self.start_sec = self.prev.ts_sec
            self.start_usec = self.prev.ts_usec
        ts_sec = self.prev.ts_sec - self.start_sec
        if self.prev.ts_usec < self.start_usec:
            ts_sec -= 1
            ts_usec = MICROSECOND - (self.start_usec - self.prev.ts_usec)
        else:
            ts_usec = self.prev.ts_usec - self.start_usec
        return self.prev, ts_sec, ts_usec

    def get_state(self):
        return self.state_urbs

    def set_state(self, state):
        for item in state:
            print(self.parse_urb(item.tobytes())[0].decode())
        self.start_sec = 0
