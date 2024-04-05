#!/usr/bin/env python

import pcapng
import sys
from dataclasses import dataclass
import struct
import errno

urb_start = struct.Struct("LBBBBHccliiII")
urb_setup = struct.Struct("BBHHH")
urb_iso = struct.Struct("ii") # no idea how this works
urb_end = struct.Struct("iiII")

desc_start = struct.Struct("BB")
desc_device = struct.Struct("HBBBBHHHBBBB")
desc_config = struct.Struct("HBBBBB")
desc_interface = struct.Struct("BBBBBBB")
desc_endpoint = struct.Struct("BBHB")

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

class UnknownURBException(Exception):
    pass

@dataclass
class HwInterface:
    link_type : int
    name : str

@dataclass(frozen=True)
class DevMap:
    bus : int
    device : int

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
               f"{chrbyte(data[i+12])}{chrbyte(data[i+13])}{chrbyte(data[i+14])}{chrbyte(data[i+15])}\n"
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
        ret += "\n"
    return ret

@dataclass
class Interface:
    interface_id : int
    alternate_setting : int
    num_endpoints : int
    interface_class : int
    subclass : int
    protocol : int
    interface_string : int | str

    def set_string(self, index, value):
        if self.interface_string == index:
            self.interface_string = value
            return True
        return False

@dataclass
class Configuration:
    total_length : int
    num_interfaces : int
    configuration_id : int
    configuration_string : int | str
    attributes : int
    max_power : int

    ATTRIB_SELF_POWERED = 0x40
    ATTRIB_REMOTE_WAKEUP = 0x20

    def set_string(self, index, value):
        found = False
        if self.configuration_string == index:
            self.configuration_string = value
            found = True
        try:
            self.interfaces
        except AttributeError:
            return found
        for interface in self.interfaces:
            if interface.set_string(index, value):
                found = True
        return found

    def add_interface(self, interface):
        try: # create the interfaces list if it doens't already exist
            self.interfaces
        except AttributeError:
            self.interfaces = []
        self.interfaces.append(interface)

    def __str__(self):
        ret = f"Configuration  Total Length: {self.total_length} Interfaces: {self.num_interfaces}" \
              f" Num: {self.configuration_id}"
        if isinstance(self.configuration_string, int):
            ret += f" Configuration String Index: {self.configuration_string}"
        else:
            ret += f" Configuration String: {self.configuration_string}"
        ret += f" Attributes: {hex(self.attributes)}"
        if self.attributes & self.ATTRIB_SELF_POWERED:
            ret += f" Self-Powered"
        if self.attributes & self.ATTRIB_REMOTE_WAKEUP:
            ret += f" Remote-Wakeup"
        ret += f" Max Power: {self.max_power*2}mA"
        return ret

@dataclass
class Device:
    usb : int
    dev_class : int
    sub_class : int
    protocol : int
    max_packet_size : int
    vendor : int
    product : int
    device : int
    # _string values start with a descriptor index which may be filled later
    manufacturer_string : int | str
    product_string : int | str
    serial_number_string : int | str
    num_configs : int

    def add_configuration(self, configuration):
        try: # create the configuration list if it doens't already exist
            self.configurations
        except AttributeError:
            self.configurations = []
        self.configurations.append(configuration)

    def set_string(self, index, value):
        found = False
        if self.manufacturer_string == index:
            self.manufacturer_string = value
            found = True
        elif self.product_string == index:
            self.product_string = value
            found = True
        elif self.serial_number_string == index:
            self.serial_number_string = value
            found = True
        try:
            self.configurations
        except AttributeError:
            return found
        for config in self.configurations:
            if config.set_string(index, value):
                found = True
        return found

    def __eq__(self, other):
        # I don't know the official way to compare devices, and the serial number isn't guaranteed to be known yet
        return self.vendor == other.vendor and self.product == other.product and self.device == other.device

    def __str__(self):
        ret = f"Device  USB Spec: {strbcd(self.usb)} Class: {self.dev_class} Subclass: {self.sub_class}" \
              f" Protocol: {self.protocol} Max Packet Size: {self.max_packet_size} Vendor: {hex(self.vendor)}" \
              f" Product: {hex(self.product)} Device Ver.: {strbcd(self.device)}"
        if isinstance(self.manufacturer_string, int):
            ret += f" Manufacturer String Index: {self.manufacturer_string}"
        else:
            ret += f" Manufacturer String: \"{self.manufacturer_string}\""
        if isinstance(self.product_string, int):
            ret += f" Product String Index: {self.product_string}"
        else:
            ret += f" Product String: \"{self.product_string}\""
        if isinstance(self.serial_number_string, int):
            ret += f" Serial Number String Index: {self.serial_number_string}"
        else:
            ret += f" Serial Number String String: \"{self.serial_number_string}\""
        ret += f" Number of Configurations: {self.num_configs}"
        return ret


@dataclass
class SetupURB:
    bmRequestType : int
    bRequest : int
    wValue : int
    wIndex : int
    wLength : int

    parent : "URB"

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
    REQUEST_GET_INTERFACE = 0x0A
    REQUEST_SET_INTERFACE = 0x11
    REQUEST_SYNCH_FRAME = 0x12

    def __str__(self):
        setup_direction = "Host-To-Device"
        if self.bmRequestType & self.TYPE_DIR_DEVICE_TO_HOST:
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
        match self.bmRequestType & self.TYPE_RECIPIENT_MASK:
            case self.TYPE_RECIPIENT_DEVICE:
                setup_recipient = "Device"
            case self.TYPE_RECIPIENT_INTERFACE:
                setup_recipient = "Interface"
            case self.TYPE_RECIPIENT_ENDPOINT:
                setup_recipient = "Endpoint"
            case self.TYPE_RECIPIENT_OTHER:
                setup_recipient = "Other"
        setup_request = "Unknown"
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
                setup_request = "GET_DESCRIPTOR"
            case self.REQUEST_SET_DESCRIPTOR:
                setup_request = "SET_DESCRIPTOR"
            case self.REQUEST_GET_CONFIGURATION:
                setup_request = "GET_CONFIGURATION"
            case self.REQUEST_SET_CONFIGURATION:
                setup_request = "SET_CONFIGURATION"
                # interfaces
            case self.REQUEST_GET_INTERFACE:
                setup_request = "GET_INTERFACE"
            case self.REQUEST_SET_INTERFACE:
                setup_request = "SET_INTERFACE"
                # endpoints
            case self.REQUEST_SYNCH_FRAME:
                setup_request = "SYNCH_FRAME"

        return f"Setup Direction: {setup_direction}, Setup Type: {setup_type}, " \
               f"Setup Recipient: {setup_recipient}, Setup Request: {setup_request}, " \
               f"Setup Value: {self.wValue}, Setup Index: {self.wIndex}, " \
               f"Setup Data Length: {self.wLength}"

    def decode(self):
        ret = "Setup Request Interpretation Unimplemented"
        match (self.bmRequestType, self.bRequest):
            case (self.TYPE_DIR_DEVICE_TO_HOST | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_GET_STATUS):
                ret = f"Setup Request Device Status"
            case (self.TYPE_DIR_HOST_TO_DEVICE | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_CLEAR_FEATURE):
                ret = f"Setup Request Clear Feature {self.wValue}"
            case (self.TYPE_DIR_HOST_TO_DEVICE | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_SET_FEATURE):
                ret = f"Setup Request Set Feature {self.wValue}"
            case (self.TYPE_DIR_HOST_TO_DEVICE | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_SET_ADDRESS):
                ret = f"Setup Request Set Address to {self.wValue}"
            case (self.TYPE_DIR_DEVICE_TO_HOST | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_GET_DESCRIPTOR):
                ret = f"Setup Request Get Descriptor {self.wValue}  Language ID: {self.wIndex}  Requested Length: {self.wLength}"
            case (self.TYPE_DIR_HOST_TO_DEVICE | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_SET_DESCRIPTOR):
                ret = f"Setup Request Set Descriptor {self.wValue}  Language ID: {self.wIndex}  Reported Length: {self.wLength}"
            case (self.TYPE_DIR_DEVICE_TO_HOST | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_GET_CONFIGURATION):
                ret = f"Setup Request Get Configuration"
            case (self.TYPE_DIR_HOST_TO_DEVICE | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_SET_CONFIGURATION):
                ret = f"Setup Request Set Configuration {self.wValue}"
        return ret

@dataclass
class ISOURB:
    error_count : int
    numdesc : int

@dataclass
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

    URB_TYPE_COMPLETE = 67 # 'C"
    URB_TYPE_SUBMIT = 83 # 'S'

    XFER_TYPE_ISO = 0
    XFER_TYPE_INTERRUPT = 1
    XFER_TYPE_CONTROL = 2
    XFER_TYPE_BULK = 3

    ENDPOINT_DIR_MASK = 0xF0
    ENDPOINT_DIR_OUT = 0x00
    ENDPOINT_DIR_IN = 0x80

    FLAG_DATA_PRESENT = 61 #'='

    DESC_TYPE_DEVICE = 1
    DESC_TYPE_CONFIGURATION = 2
    DESC_TYPE_STRING = 3
    DESC_TYPE_INTERFACE = 4
    DESC_TYPE_ENDPOINT = 5


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
        direction = f"Unknown {self.epnum}"
        match self.epnum & self.ENDPOINT_DIR_MASK:
            case self.ENDPOINT_DIR_OUT:
                direction = "Out/Host"
            case self.ENDPOINT_DIR_IN:
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

    def __init__(self, data, prev):
        self.prev = prev
        # get beginning
        urb_id, urb_type, xfer_type, epnum, devnum, busnum, flag_setup, flag_data, ts_sec, ts_nsec, status, length, len_cap = urb_start.unpack(data[:urb_start.size])
        # get end
        interval, start_frame, xfer_flags, ndesc = urb_end.unpack(data[urb_start.size+urb_iso.size:urb_start.size+urb_iso.size+urb_end.size])
        if xfer_type == self.XFER_TYPE_CONTROL:
            bmRequestType, bRequest, wValue, wIndex, wLength = urb_setup.unpack(data[urb_start.size:urb_start.size+urb_setup.size])
            self.urb_id = urb_id
            self.urb_type = urb_type
            self.xfer_type = xfer_type
            self.epnum = epnum
            self.devnum = devnum
            self.busnum = busnum
            self.flag_setup = flag_setup
            self.flag_data = flag_data
            self.ts_sec = ts_sec
            self.ts_nsec = ts_nsec
            self.status = status
            self.length = length
            self.len_cap = len_cap
            self.extra = SetupURB(bmRequestType, bRequest, wValue, wIndex, wLength, self)
            self.interval = interval
            self.start_frame = start_frame
            self.xfer_flags = xfer_flags
            self.ndesc = ndesc
        else:
            raise UnknownURBException()
        self.data = data[urb_start.size+urb_iso.size+urb_end.size:]

    def __str__(self):
        urb_type_str, xfer_type_str, direction, data_present, status_str = self.field_decode()
        ret = f"URB ID: {self.urb_id:X}, URB Type: {urb_type_str}, Transfer Type: {xfer_type_str}, " \
              f"Direction/Subject: {direction}, Endpoint: {self.epnum & 0x0F}, " \
              f"Device: {self.devnum}, Bus: {self.busnum}, Setup Flag: {self.flag_setup}, " \
              f"Data Flag: {data_present}, Time: {self.ts_sec}, {self.ts_nsec}, " \
              f"Status: {status_str}, Requested Packet Length: {self.length}, " \
              f"Captured Length: {self.len_cap}, {self.extra}, Interval: {self.interval}, " \
              f"Start Frame: {self.start_frame}, Transfer Flags: {self.xfer_flags}, " \
              f"ISO Descriptors: {self.ndesc}\n"
        if len(self.data) > 0:
            ret += f"{str_hex(self.data)}"
        return ret

    def decode_setup_response(self):
        if self.prev.xfer_type != URB.XFER_TYPE_CONTROL:
            return "Previous packet wasn't a Control type"
        prev_setup = self.prev.extra
        match (prev_setup.bmRequestType, prev_setup.bRequest):
            case (SetupURB.TYPE_DIR_DEVICE_TO_HOST | SetupURB.TYPE_STANDARD | SetupURB.TYPE_RECIPIENT_DEVICE, SetupURB.REQUEST_GET_DESCRIPTOR):
                return f"Get Descriptor Response {prev_setup.wValue}"
        return "Response Interpretation Unimplemented"

    def add_new_device(new_dev, new_dev_map):
        devices.append(new_dev)
        devmap[new_dev_map] = devices[-1]

    def decode(self):
        if self.urb_type == self.URB_TYPE_COMPLETE:
            # Responses
            match self.xfer_type:
                case self.XFER_TYPE_CONTROL:
                    desc_len, desc_type = desc_start.unpack(self.data[:desc_start.size])
                    match desc_type:
                        case self.DESC_TYPE_DEVICE:
                            usb, dev_class, sub_class, protocol, max_packet_size, vendor, product, device, manufacturer_string, product_string, serial_number_string, num_configs = desc_device.unpack(self.data[desc_start.size:])
                            new_dev = Device(usb, dev_class, sub_class, protocol, max_packet_size, vendor, product, device, manufacturer_string, product_string, serial_number_string, num_configs)
                            new_dev_map = DevMap(self.busnum, self.devnum)
                            if new_dev_map in devmap:
                                if new_dev == devmap[new_dev_map]:
                                    return f"Ignoring same device in {new_dev_map.bus}.{new_dev_map.device}: {new_dev}"
                                else:
                                    URB.add_new_device(new_dev, new_dev_map)
                                    return f"Replacement in {new_dev_map.bus}.{new_dev_map.device}: {new_dev}"
                            URB.add_new_device(new_dev, new_dev_map)
                            return str(new_dev)
                        case self.DESC_TYPE_CONFIGURATION:
                            total_length, num_interfaces, configuration_id, configuration_string, attributes, max_power = desc_config.unpack(self.data[desc_start.size:desc_start.size+desc_config.size])
                            new_config = Configuration(total_length, num_interfaces, configuration_id, configuration_string, attributes, max_power)
                            if len(self.data) < total_length:
                                return f"Ignoring Incomplete Configuration Response: {new_config}"
                            # decode following interfaces/endpoints/HIDs
                            pos = desc_start.size + desc_config.size
                            for i in range(num_interfaces):
                                interface_id, alternate_setting, num_endpoints, interface_class, subclass, protocol, interface_string = desc_interface.unpack(self.data[pos:pos+desc_interface.size])
                                pos += desc_interface.size
                                new_interface = Interface(interface_id, alternate_setting, num_endpoints, interface_class, subclass, protocol, interface_string)

                            devmap[DevMap(self.busnum, self.devnum)].add_configuration(new_config)
                            return f"Configuration Response: {new_config}"
                        #case self.DESC_TYPE_STRING:
                        #case self.DESC_TYPE_INTERFACE:
                        #case self.DESC_TYPE_ENDPOINT:
                    return f"Unsupported Control Response: {self.decode_setup_response()}"
        else: # Submit
            # Requests
            match self.xfer_type:
                case self.XFER_TYPE_CONTROL:
                    return self.extra.decode()
        return "Interpretation Unimplemented"

def decode(infile):
    scanner = pcapng.FileScanner(infile)
    urb = None
    for block in scanner:
        if isinstance(block, pcapng.blocks.SectionHeader):
            print("Section Header")
        elif isinstance(block, pcapng.blocks.InterfaceDescription):
            interfaces.append(HwInterface(block.link_type, block.options['if_name']))
            print(f"Interface Description {interfaces[-1].name}")
        elif isinstance(block, pcapng.blocks.EnhancedPacket):
            print(f"{interfaces[block.interface_id].name} {block.packet_len}", end='')
            if block.captured_len < block.packet_len:
                print(f" {block.captured_len}")
            else:
                print()
            #print(str_hex(block.packet_data))
            try:
                urb = URB(block.packet_data, urb)
                print(urb, end='')
                print(urb.decode())
            except Exception as e:
                print(str_hex(block.packet_data))
                raise e
        elif isinstance(block, pcapng.blocks.InterfaceStatistics):
            print("s", end='')
        else:
            print("Unhandled block type")
            print(block)
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
        with open(sys.argv[1], 'rb') as infile:
            decode(infile)
