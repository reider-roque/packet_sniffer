import socket


class ByKeyOrValue(object):
    _set_of_pairs = set()

    @classmethod
    def get(cls, key_or_value, default="Unknown"):
        for pair in cls._set_of_pairs:
            if pair[0] == key_or_value:
                return pair[1]
            elif pair[1] == key_or_value:
                return pair[0]

        return default


class EtherTypes(ByKeyOrValue):
    _set_of_pairs = {
        ("IPv4", 0x0800),
        ("ARP", 0x0806),
        ("RARP", 0x8035),
        ("SNMP", 0x814c),
        ("IPv6", 0x86dd)
    }


class IPVersions(ByKeyOrValue):
    _set_of_pairs = {
        ("IPv4", 4),
        ("IPv6", 6)
    }


class TransportProtocols(ByKeyOrValue):
    _set_of_pairs = {
        ("ICMP", 1),
        ("TCP", 6),
        ("UDP", 17)
    }


# Header and footer formatting functions
def print_section_header(s):
    print("{:=^78}".format(" " + s + " "))


def print_section_footer():
    print("{:=^78}\n".format(""))


def print_output(label, format_str, *format_values):
    print(("{:<30} " + format_str).format(label, *format_values))


def format_field(field, field_type):

    if field_type == "mac":
        # Format a MAC address as XX:XX:XX:XX:XX:XX
        byte_str = ["{:02x}".format(field[i])
                    for i in range(0, len(field))]
        return ":".join(byte_str)
    elif field_type == "ethertype":
       return EtherTypes.get(field)
    elif field_type == "ipver":
        return IPVersions.get(field)
    elif field_type == "transproto":
        return TransportProtocols.get(field)



