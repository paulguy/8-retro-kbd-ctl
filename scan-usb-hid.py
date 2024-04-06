#!/usr/bin/env python

import pcapng
import sys
from dataclasses import dataclass
import struct
import errno

urb_start = struct.Struct("LBBBBHBBliiII")
urb_setup = struct.Struct("BBHHH")
urb_iso = struct.Struct("ii") # no idea how this works
urb_end = struct.Struct("iiII")

desc_start = struct.Struct("BB")
desc_device = struct.Struct("HBBBBHHHBBBB")
desc_config = struct.Struct("HBBBBB")
desc_interface = struct.Struct("BBBBBBB")
desc_endpoint = struct.Struct("BBHB")

# I guess python really does suck
iface_hid = struct.Struct("<HBBBH")

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

def get_better_string(orig, new):
    # if the new string is a truncated version of the original
    # just keep the original
    if orig.startswith(new):
        return False, orig
    # otherwise, apply the new string
    return True, new

@dataclass
class Endpoint:
    address : int
    attributes : int
    max_packet_size : int
    interval : int

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

@dataclass
class HID:
    hid : int
    country_code : int
    num_descriptor : int
    descriptor_type : int
    descriptor_length : int

    def __str__(self):
        return f"HID  ID: {strbcd(self.hid)} Country Code: {self.country_code}" \
               f" Descriptors: {self.num_descriptor} Type: {self.descriptor_type}" \
               f" Descriptor Length: {self.descriptor_length}"

@dataclass
class Interface:
    interface_id : int
    alternate_setting : int
    num_endpoints : int
    interface_class : int
    subclass : int
    protocol : int
    interface_string_id : int

    def set_string(self, index, value):
        try: # create the string if it doesn't already exist
            self.interface_string
        except AttributeError:
            self.interface_string = ""
        if self.interface_string_id == index:
            used, self.interface_string = get_better_string(self.interface_string, value)
            return used
        return False

    def set_hid(self, hid : HID):
        self.hid = hid

    def add_endpoint(self, endpoint : Endpoint):
        try: # create the endpoints list if it doens't already exist
            self.endpoints
        except AttributeError:
            self.endpoints = []
        self.endpoints.append(endpoint)

    def __str__(self):
        ret = f"Interface  ID: {self.interface_id} Alternate Setting: {self.alternate_setting}" \
              f" Endpoints: {self.num_endpoints} Class: {self.interface_class}" \
              f" Subclass: {self.subclass} Protocol: {self.protocol}"
        try:
            ret += f" Interface String: \"{self.interface_string}\""
        except AttributeError:
            ret += f" Interface String Index: {self.interface_string_id}"
        # check first to reduce calls in try blocks to not hide further errors
        do_hid = False
        do_endpoints = False
        try:
            self.hid
            do_hid = True
        except AttributeError:
            pass
        try:
            self.endpoints
            do_endpoints = True
        except AttributeError:
            pass
        if do_hid:
            ret += f"\n{str(self.hid)}"
        if do_endpoints:
            for endpoint in self.endpoints:
                ret += f"\n{str(endpoint)}"
        return ret

@dataclass
class Configuration:
    total_length : int
    num_interfaces : int
    configuration_id : int
    configuration_string_id : int
    attributes : int
    max_power : int

    ATTRIB_SELF_POWERED = 0x40
    ATTRIB_REMOTE_WAKEUP = 0x20

    def set_string(self, index, value):
        found = False
        try: # create the string if it doesn't already exist
            self.configuration_string
        except AttributeError:
            self.configuration_string = ""
        if self.configuration_string_id == index:
            found, self.configuration_string = get_better_string(self.configuration_string, value)

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
        try:
            ret += f" Configuration String: \"{self.configuration_string}\""
        except AttributeError:
            ret += f" Configuration String Index: {self.configuration_string_id}"
        ret += f" Attributes: {self.attributes:04X}"
        if self.attributes & self.ATTRIB_SELF_POWERED:
            ret += f" Self-Powered"
        if self.attributes & self.ATTRIB_REMOTE_WAKEUP:
            ret += f" Remote-Wakeup"
        ret += f" Max Power: {self.max_power*2}mA"
        try:
            self.interfaces
        except AttributeError:
            return ret
        for interface in self.interfaces:
            ret += f"\n{str(interface)}"
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
    manufacturer_string_id : int
    product_string_id : int
    serial_number_string_id : int
    num_configs : int

    def add_configuration(self, configuration):
        try: # create the configuration list if it doens't already exist
            self.configurations
        except AttributeError:
            self.configurations = []
        self.configurations.append(configuration)

    def set_string(self, index, value):
        found = False
        try: # create the string if it doesn't already exist
            self.manufacturer_string
        except AttributeError:
            self.manufacturer_string = ""
        if self.manufacturer_string_id == index:
            found, self.manufacturer_string = get_better_string(self.manufacturer_string, value)

        try:
            self.product_string
        except AttributeError:
            self.product_string = ""
        if self.product_string_id == index:
            used, self.product_string = get_better_string(self.product_string, value)
            if used:
                found = True

        try:
            self.serial_number_string
        except AttributeError:
            self.serial_number_string = ""
        if self.serial_number_string_id == index:
            used, self.serial_number_string = get_better_string(self.serial_number_string, value)
            if used:
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
              f" Protocol: {self.protocol} Max Packet Size: {self.max_packet_size} Vendor: {self.vendor:04X}" \
              f" Product: {self.product:04X} Device Ver.: {strbcd(self.device)}"
        try:
            ret += f" Manufacturer String: \"{self.manufacturer_string}\""
        except AttributeError:
            ret += f" Manufacturer String Index: {self.manufacturer_string_id}"
        try:
            ret += f" Product String: \"{self.product_string}\""
        except AttributeError:
            ret += f" Product String Index: {self.product_string_id}"
        try:
            ret += f" Serial Number String String: \"{self.serial_number_string}\""
        except AttributeError:
            ret += f" Serial Number String Index: {self.serial_number_string_id}"
        ret += f" Number of Configurations: {self.num_configs}"
        try:
            self.configurations
        except AttributeError:
            return ret
        for config in self.configurations:
            ret += f"\n{str(config)}"
        return ret

@dataclass
class SetupURB:
    bmRequestType : int
    bRequest : int
    wValue : int
    wIndex : int
    wLength : int

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
    DESCRIPTOR_DEVICE = 0x0100
    DESCRIPTOR_CONFIGURATION = 0x0200
    DESCRIPTOR_STRING = 0x0300
    DESCRIPTOR_INTERFACE = 0x0400
    DESCRIPTOR_ENDPOINT = 0x0500
    DESCRIPTOR_DEVICE_QUALIFIER = 0x0600
    DESCRIPTOR_OTHER_SPEED_CONFIGURATION = 0x0700
    DESCRIPTOR_INTERFACE_POWER = 0x0800
    DESCRIPTOR_ON_THE_GO = 0x0900

    def direction(self):
        return self.bmRequestType & self.TYPE_DIR_MASK

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
                        setup_request = "GET_DESCRIPTOR"
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

    def get_value_desc(self):
        return self.wValue & self.DESCRIPTOR_MASK

    def get_value_index(self):
        return self.wValue & self.INDEX_MASK

    def descriptor_string(self):
        match self.get_value_desc():
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
        return "Unknown"

    def decode(self):
        ret = f"Setup Request Interpretation Unimplemented {self.bmRequestType:02X} {self.bRequest:02X}"
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
                ret = f"Setup Request Get Descriptor {self.descriptor_string()}" \
                      f" {self.get_value_index()} Language ID: {self.wIndex}" \
                      f" Requested Length: {self.wLength}"
            case (self.TYPE_DIR_HOST_TO_DEVICE | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_SET_DESCRIPTOR):
                ret = f"Setup Request Set Descriptor {self.descriptor_string()}" \
                      f" {self.get_value_index()} Language ID: {self.wIndex}" \
                      f" Requested Length: {self.wLength}"
            case (self.TYPE_DIR_DEVICE_TO_HOST | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_GET_CONFIGURATION):
                ret = f"Setup Request Get Configuration"
            case (self.TYPE_DIR_HOST_TO_DEVICE | self.TYPE_STANDARD | self.TYPE_RECIPIENT_DEVICE, self.REQUEST_SET_CONFIGURATION):
                ret = f"Setup Request Set Configuration {self.wValue}"
            #case (self.TYPE_DIR_HOST_TO_DEVICE | self.TYPE_CLASS | self.TYPE_RECIPIENT_INTERFACE, self.REQUEST_SET_IDLE):
            case (0x21, 0x0A): # dunno why this doesn't work
                ret = "Setup Request Set Idle"
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

    INTERFACE_CLASS_HID = 3

    HID_DESCRIPTOR_TYPE = 0x22

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
        if self.direction == self.ENDPOINT_DIR_IN:
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

        self.urb_id = urb_id
        self.urb_type = urb_type
        self.xfer_type = xfer_type
        self.epnum = epnum
        self.direction = self.epnum & self.ENDPOINT_DIR_MASK
        self.endpoint = self.epnum & self.ENDPOINT_MASK
        self.devnum = devnum
        self.busnum = busnum
        self.flag_setup = flag_setup
        self.flag_data = flag_data
        self.ts_sec = ts_sec
        self.ts_nsec = ts_nsec
        self.status = status
        self.length = length
        self.len_cap = len_cap
        self.interval = interval
        self.start_frame = start_frame
        self.xfer_flags = xfer_flags
        self.ndesc = ndesc

        if xfer_type == self.XFER_TYPE_CONTROL:
            if self.flag_setup == self.FLAG_SETUP:
                bmRequestType, bRequest, wValue, wIndex, wLength = urb_setup.unpack(data[urb_start.size:urb_start.size+urb_setup.size])
                self.extra = SetupURB(bmRequestType, bRequest, wValue, wIndex, wLength, self)
        elif xfer_type == self.XFER_TYPE_INTERRUPT:
            pass
        else:
            raise UninterpretableDataException(f"Unknown transfer type {xfer_type}")

        self.data = data[urb_start.size+urb_iso.size+urb_end.size:]

    def __str__(self):
        urb_type_str, xfer_type_str, direction, data_present, status_str = self.field_decode()
        ret = f"URB ID: {self.urb_id:X}, URB Type: {urb_type_str}, Transfer Type: {xfer_type_str}, " \
              f"Direction/Subject: {direction}, Endpoint: {self.endpoint}, " \
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

    def add_new_device(new_dev, new_dev_map):
        devices.append(new_dev)
        devmap[new_dev_map] = devices[-1]

    def str_endpoint(self):
        return f"{self.busnum}.{self.devnum}.{self.endpoint}"

    def decode(self):
        if -self.status not in (0, errno.EINPROGRESS):
            return f"{self.str_endpoint()} Error {-self.status} {errno.errorcode[-self.status]}"

        match self.xfer_type:
            case self.XFER_TYPE_CONTROL:
                if self.flag_setup == self.FLAG_SETUP:
                    # setup request
                    return f"{self.str_endpoint()} {self.extra.decode()}"
                else:
                    # responses
                    if len(self.data) == 0:
                        prev_setup = self.prev.extra
                        match (prev_setup.bmRequestType, prev_setup.bRequest):
                            case (SetupURB.TYPE_DIR_DEVICE_TO_HOST | SetupURB.TYPE_STANDARD | SetupURB.TYPE_RECIPIENT_DEVICE,
                                  SetupURB.REQUEST_SET_CONFIGURATION):
                                return f"{self.str_endpoint()} Set Configuration Response {prev_setup.wValue}"
                            case (0x21, 0x0A): # as above...
                                return f"{self.str_endpoint()} Set Idle Response"
                    else:
                        desc_len, desc_type = desc_start.unpack(self.data[:desc_start.size])
                        match desc_type:
                            case self.DESC_TYPE_DEVICE:
                                usb, dev_class, sub_class, protocol, max_packet_size, vendor, product, device, manufacturer_string, product_string, serial_number_string, num_configs = desc_device.unpack(self.data[desc_start.size:])
                                new_dev = Device(usb, dev_class, sub_class, protocol, max_packet_size, vendor, product, device, manufacturer_string, product_string, serial_number_string, num_configs)
                                new_dev_map = DevMap(self.busnum, self.devnum)
                                if new_dev_map in devmap:
                                    if new_dev == devmap[new_dev_map]:
                                        return f"{self.str_endpoint()} Ignoring same device in {new_dev_map.bus}.{new_dev_map.device}: {new_dev}"
                                    else:
                                        URB.add_new_device(new_dev, new_dev_map)
                                        return f"{self.str_endpoint()} Replacement in {new_dev_map.bus}.{new_dev_map.device}: {new_dev}"
                                URB.add_new_device(new_dev, new_dev_map)
                                return f"{self.str_endpoint()} {str(new_dev)}"
                            case self.DESC_TYPE_CONFIGURATION:
                                total_length, num_interfaces, configuration_id, configuration_string, attributes, max_power = desc_config.unpack(self.data[desc_start.size:desc_start.size+desc_config.size])
                                new_config = Configuration(total_length, num_interfaces, configuration_id, configuration_string, attributes, max_power)
                                if len(self.data) < total_length:
                                    return f"{self.str_endpoint()} Ignoring Incomplete Configuration Response: {new_config}"
                                # decode following interfaces/endpoints/HIDs
                                pos = desc_start.size + desc_config.size
                                for i in range(num_interfaces):
                                    pos += desc_start.size # don't bother decoding the lengths and types...
                                    interface_id, alternate_setting, num_endpoints, interface_class, subclass, protocol, interface_string = desc_interface.unpack(self.data[pos:pos+desc_interface.size])
                                    pos += desc_interface.size
                                    new_interface = Interface(interface_id, alternate_setting, num_endpoints, interface_class, subclass, protocol, interface_string)
                                    if interface_class == self.INTERFACE_CLASS_HID:
                                        pos += desc_start.size
                                        hid, country_code, num_descriptors, descriptor_type, descriptor_length = iface_hid.unpack(self.data[pos:pos+iface_hid.size])
                                        pos += iface_hid.size
                                        new_hid = HID(hid, country_code, num_descriptors, descriptor_type, descriptor_length)
                                        new_interface.set_hid(new_hid)
                                    else:
                                        raise UninterpretableDataException(f"Unknown interface class {interface_class}")
                                    for j in range(num_endpoints):
                                        pos += desc_start.size
                                        address, attributes, max_packet_size, interval = desc_endpoint.unpack(self.data[pos:pos+desc_endpoint.size])
                                        pos += desc_endpoint.size
                                        new_endpoint = Endpoint(address, attributes, max_packet_size, interval)
                                        new_interface.add_endpoint(new_endpoint)
                                    new_config.add_interface(new_interface)
                                devmap[DevMap(self.busnum, self.devnum)].add_configuration(new_config)
                                return f"{self.str_endpoint()} Configuration Response: {new_config}"
                            case self.DESC_TYPE_STRING:
                                index = self.prev.extra.get_value_index()
                                if index == 0:
                                    ret = f"{self.str_endpoint()} String Languages Response:"
                                    for i in range(desc_start.size, desc_len-desc_start.size+1, 2):
                                        ret += f" {self.data[i] | (self.data[i+1] << 8):04X}"
                                    return ret
                                new_str = self.data[desc_start.size:].decode('utf-16')
                                used = devmap[DevMap(self.busnum, self.devnum)].set_string(index, new_str)
                                used_str = "Not Used"
                                if used:
                                    used_str = "Used"
                                return f"{self.str_endpoint()} String Response: \"{new_str}\" {used_str}"
                            #case self.DESC_TYPE_INTERFACE:
                            #case self.DESC_TYPE_ENDPOINT:
                return f"{self.str_endpoint()} Unsupported Control Response"
            case self.XFER_TYPE_INTERRUPT:
                if self.direction == self.ENDPOINT_DIR_IN:
                    ret = "Interrupt Packet In"
                    if len(self.data) == 0:
                        ret += " No Data"
                    return ret
                else:
                    pass
        return "{self.str_endpoint()} Interpretation Unimplemented"

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
                urb = URB(block.packet_data, urb)
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
