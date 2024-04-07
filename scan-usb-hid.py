#!/usr/bin/env python

import pcapng
import sys
from dataclasses import dataclass
import struct
import errno

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

    def __init__(self, data):
        length, desc, self.address, self.attributes, self.max_packet_size, self.interval = \
            self.struct.unpack(data[:self.struct.size])

    def __str__(self):
        addr_num = self.address & self.ADDRESS_MASK
        addr_dir = "Out"
        if self.address & self.ADDRESS_DIR_MASK == self.ADDRESS_DIR_IN:
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
        return f"Endpoint  Address: {addr_num} {addr_dir}" \
               f" Attributes: {self.attributes} {attrib_type}{attrib_iso_sync}{attrib_iso_usage}" \
               f" Max Packet Size: {self.max_packet_size} Interval: {self.interval}"

class HID:
    hid : int
    country_code : int
    num_descriptor : int
    descriptor_type : int
    descriptor_length : int

    # I guess python really does suck
    # specify endianness to ignore alignment?
    struct = struct.Struct("<BBHBBBH")

    def decode(self, data):
        # TODO: Decide HID
        pass

    def __init__(self, data):
        length, desc, self.hid, self.country_code, self.num_descriptors, self.descriptor_type, \
            self.descriptor_length = self.struct.unpack(data[:self.struct.size])

    def __str__(self):
        return f"HID  ID: {strbcd(self.hid)} Country Code: {self.country_code}" \
               f" Descriptors: {self.num_descriptors} Type: {self.descriptor_type}" \
               f" Descriptor Length: {self.descriptor_length}"

class Interface:
    interface_id : int
    alternate_setting : int
    num_endpoints : int
    interface_class : int
    subclass : int
    protocol : int
    interface_string_id : int

    struct = struct.Struct("BBBBBBBBB")

    INTERFACE_CLASS_HID = 3

    def set_string(self, index, value):
        if self.interface_string_id == index:
            used, self.interface_string = get_better_string(self.interface_string, value)
            return used
        return False

    def get_size(self):
        hidsize = 0
        if self.interface_class == self.INTERFACE_CLASS_HID:
            hidsize = HID.struct.size
        return len(self.endpoints) * Endpoint.struct.size + self.struct.size + hidsize

    def decode_hid(self, data):
        self.hid.decode(data)

    def __init__(self, data):
        length, desc, self.interface_id, self.alternate_setting, self.num_endpoints, \
            self.interface_class, self.subclass, self.protocol, \
            self.interface_string_id = self.struct.unpack(data[:self.struct.size])
        self.endpoints = []
        pos = self.struct.size
        if self.interface_class == self.INTERFACE_CLASS_HID:
            self.hid = HID(data[pos:])
            pos += HID.struct.size
        else:
            raise UninterpretableDataException(f"Unknown interface class {self.interface_class}")
        for j in range(self.num_endpoints):
            self.endpoints.append(Endpoint(data[pos:]))
            pos += Endpoint.struct.size
        self.interface_string = ""

    def __str__(self):
        ret = f"Interface  ID: {self.interface_id} Alternate Setting: {self.alternate_setting}" \
              f" Endpoints: {self.num_endpoints} Class: {self.interface_class}" \
              f" Subclass: {self.subclass} Protocol: {self.protocol}"
        if len(self.interface_string) == 0:
            ret += f" Interface String Index: {self.interface_string_id}"
        else:
            ret += f" Interface String: \"{self.interface_string}\""
        if self.interface_class == self.INTERFACE_CLASS_HID:
            ret += f"\n{self.hid}"
        for endpoint in self.endpoints:
            ret += f"\n{endpoint}"
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
        self.interfaces = []
        if len(data) >= self.total_length - URB.SIZE:
            # decode following interfaces
            pos = self.struct.size
            for i in range(self.num_interfaces):
                self.interfaces.append(Interface(data[pos:]))
                pos += self.interfaces[-1].get_size()
        self.configuration_string = ""

    def set_string(self, index, value):
        found = False
        if self.configuration_string_id == index:
            found, self.configuration_string = get_better_string(self.configuration_string, value)

        for interface in self.interfaces:
            if interface.set_string(index, value):
                found = True
        return found

    def decode_hid(self, interface, data):
        for iface in self.interfaces:
            if iface.interface_id == interface:
                iface.decode_hid(data)

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
        for interface in self.interfaces:
            ret += f"\n{str(interface)}"
        return ret

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

    def decode_hid(self, interface, data):
        self.configurations[self.configuration].decode_hid(interface, data)

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
        for config in self.configurations:
            ret += f"\n{str(config)}"
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
                                        devmap[self.dev_map].decode_hid(prev.extra.get_desc_index(), self.data)
            case self.XFER_TYPE_INTERRUPT:
                if len(self.data) == 0:
                    self.prev = prev

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
            ret += f", {self.extra}\n"
        else:
            ret += f"\n"
        if len(self.data) > 0:
            ret += f"{str_hex(self.data)}"
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
                                        return f"{self.str_endpoint()} HID Report Response"
                return f"{self.str_endpoint()} Unsupported Control Response"
            case self.XFER_TYPE_INTERRUPT:
                if self.direction() == self.ENDPOINT_DIR_IN:
                    ret = f"{self.str_endpoint()} Interrupt Packet In"
                    if len(self.data) == 0:
                        prev = self.prev
                        if prev.xfer_type == self.XFER_TYPE_INTERRUPT and \
                           prev.direction() == self.ENDPOINT_DIR_IN and \
                           self.urb_type == self.URB_TYPE_SUBMIT:
                            ret += " Acknowledge" 
                        else:
                            ret += " No Data"
                    return ret
                else: # Out
                    ret = f"I{self.str_endpoint()} Interrupt Packet Out"
                    if len(self.data) == 0:
                        prev = self.prev
                        if prev.xfer_type == self.XFER_TYPE_INTERRUPT and \
                           prev.direction() == self.ENDPOINT_DIR_OUT and \
                           self.urb_type == self.URB_TYPE_COMPLETE:
                            ret += " Acknowledge" 
                        else:
                            ret += " No Data"
                    return ret
        return f"{self.str_endpoint()} Interpretation Unimplemented"

def decode(infile, verbose):
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
        verbose = False
        if len(sys.argv) > 2 and sys.argv[2].lower() == "verbose":
            verbose = True
        with open(sys.argv[1], 'rb') as infile:
            decode(infile, verbose)
