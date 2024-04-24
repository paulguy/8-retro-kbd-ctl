SHIFT_MASKS_LOW = [0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01]
SHIFT_MASKS_HIGH = [0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80]
BIT_MASKS = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]

MICROSECOND = 1000000
MICROSECOND_EXP = 6

def chrbyte(char):
    if char < ord(' ') or char > ord('~'):
        return '.'
    return f"{char:c}"

def strbcd(val):
    return hex(val)[2:]

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

def bits_to_bytes(bits):
    if bits % 8 > 0:
        bits += 8
    return bits // 8

def ts_to_sec(sec, usec, precision=2):
    decimal = usec // int(10**(MICROSECOND_EXP-precision))
    decimal = float(decimal) / (10**precision)
    return float(sec) + decimal

def arg_to_num(arg):
    try:
        num = int(arg)
    except ValueError:
        if arg.startswith("0x"):
            num = int(arg[2:], base=16)
        else:
            raise ValueError("Arg is not a number!")
    return num
