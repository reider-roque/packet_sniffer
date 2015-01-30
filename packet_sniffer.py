#!/usr/bin/env python


import binascii
import struct
import sys
import textwrap


import sniff_socket
from utils import *


class EtherHeader(object):
    def __init__(self, frame):
        hdr_str = frame[0:14]
        hdr_unpacked = struct.unpack("!6B6BH", hdr_str)

        self.dst_mac = hdr_unpacked[0:6]
        self.src_mac = hdr_unpacked[6:12]
        self.eth_type = hdr_unpacked[12]

    def dump(self, num):
        print_section_header('ETHERNET HEADER #{}'.format(num))

        print_output("Source MAC", "{}", format_field(self.src_mac, "mac"))
        print_output("Destination MAC", "{}", format_field(self.dst_mac, "mac"))
        print_output("Ether Type", "0x{:04x} ({})",
                     self.eth_type, format_field(self.eth_type, "ethertype"))

        print_section_footer()


class IPFlags(object):
    def __init__(self, flag_bits):
        # Flags is an integer taking 3-bit
        # The 1st bit is reserved and is of no use
        # The 2nd bit:
        self.DF = flag_bits & 0b11 >> 1
        # The 3rd bit:
        self.MF = flag_bits & 0b1

    def __str__(self):
        result = []
        if self.DF:
            result.append("DF, ")
        if self.MF:
            result.append("MF, ")

        "".join(result)

        if result:
            return result[:-2]
        else:
            return "--"


class IPHeader(object):
    def __init__(self, frame):
        hdr_str = frame[14:34]
        hdr_unpacked = struct.unpack("!BBHHHBBH4s4s", hdr_str)

        self.ver = hdr_unpacked[0] >> 4  # High 4 bits
        # Low 4 bits hold header length in 32-bit words;
        # By multiplying by four 32-bit words are converted to bytes
        self.hdr_size = (hdr_unpacked[0] & 0b1111) * 4
        self.dscp = hdr_unpacked[1] >> 6  # High 6 bits
        self.ecn = hdr_unpacked[1] & 0b11  # Low 2 bits
        self.tlen = hdr_unpacked[2]
        self.id = hdr_unpacked[3]
        self.flags = IPFlags(hdr_unpacked[4] >> 3)
        # Low 13 bits
        self.fragoff = hdr_unpacked[4] & 0b1111111111111
        self.ttl = hdr_unpacked[5]
        self.proto = hdr_unpacked[6]
        self.check_sum = hdr_unpacked[7]
        self.src_ip = socket.inet_ntoa(hdr_unpacked[8])
        self.dst_ip = socket.inet_ntoa(hdr_unpacked[9])

    def dump(self, num):
        print_section_header('IP HEADER #{}'.format(num))

        print_output("Version", "{} ({})", self.ver, format_field(self.ver, "ipver"))
        print_output("IP Header Length", "{} bytes", self.hdr_size)
        print_output("Diff Services", "{}", self.dscp)
        print_output("Expl Congestion Notification", "{}", self.ecn)
        print_output("Total Length", "{} bytes", self.tlen)
        print_output("Identification", "0x{:04x}", self.id)
        print_output("Flags", "{}", self.flags)
        print_output("Fragment Offset", "{}", self.fragoff)
        print_output("TTL", "{}", self.ttl)
        print_output("Protocol", "{}", format_field(self.proto, "transproto"))
        print_output("Checksum", "0x{:04x}", self.check_sum)
        print_output("Source IP", "{}", self.src_ip)
        print_output("Destination IP", "{}", self.dst_ip)

        print_section_footer()


class TCPFlags(object):
    def __init__(self, flag_bits):
        self.NS = flag_bits & 0b100000000
        self.CWR = flag_bits & 0b010000000
        self.ECE = flag_bits & 0b001000000
        self.URG = flag_bits & 0b000100000
        self.ACK = flag_bits & 0b000010000
        self.PSH = flag_bits & 0b000001000
        self.RST = flag_bits & 0b000000100
        self.SYN = flag_bits & 0b000000010
        self.FIN = flag_bits & 0b000000001

    def __str__(self):
        result = []
        if self.NS:
            result.append("NS, ")
        if self.CWR:
            result.append("CWR, ")
        if self.ECE:
            result.append("ECE, ")
        if self.URG:
            result.append("URG, ")
        if self.ACK:
            result.append("ACK, ")
        if self.PSH:
            result.append("PSH, ")
        if self.RST:
            result.append("RST, ")
        if self.SYN:
            result.append("SYN, ")
        if self.FIN:
            result.append("FIN, ")

        result = "".join(result)

        if result:
            return result[:-2]
        else:
            return "--"


class TCPHeader(object):
    def __init__(self, frame, ip_hdr_length):
        hdr_offset = 14 + ip_hdr_length
        hdr_str = frame[hdr_offset:hdr_offset + 20]
        hdr_unpacked = struct.unpack("!HHLLHHHH", hdr_str)

        self.src_port = hdr_unpacked[0]
        self.dst_port = hdr_unpacked[1]
        self.seq_num = hdr_unpacked[2]
        self.ack_num = hdr_unpacked[3]
        # High 4 bits hold header length in 32-bit words;
        # By multiplying by four 32-bit words are converted to bytes
        self.hdr_size = (hdr_unpacked[4] >> 12) * 4
        # Flags are the low 9 bits of this 16 bit field
        self.flags = TCPFlags(hdr_unpacked[4] & 0b111111111)
        self.win_size = hdr_unpacked[5]
        self.check_sum = hdr_unpacked[6]
        self.urg_ptr = hdr_unpacked[7]


    def dump(self, num):
        print_section_header("TCP HEADER #{}".format(num))

        print_output("Source Port", "{}", self.src_port)
        print_output("Destination Port", "{}", self.dst_port)
        print_output("Sequence Number", "{}", self.seq_num)
        print_output("Acknowledgement number", "{}", self.ack_num)
        print_output("TCP Header Length", "{} bytes", self.hdr_size)
        print_output("TCP Flags", "{}", self.flags)
        print_output("Window size", "{}", self.win_size)
        print_output("Checksum", "{}", self.check_sum)
        print_output("Urgent Pointer", "{}", self.urg_ptr)

        print_section_footer()


class TCPPacket():
    # How many packets have been created
    num = 0

    def __init__(self, frame):
        TCPPacket.num += 1

        self.ether_header = EtherHeader(frame)
        self.ip_header = IPHeader(frame)
        self.tcp_header = TCPHeader(frame, self.ip_header.hdr_size)

        tcp_payload_offset = self.ip_header.hdr_size + self.tcp_header.hdr_size
        tcp_payload = binascii.hexlify(frame[tcp_payload_offset:]).decode()
        self.tcp_payload = " ".join(a + b
                                    for (a, b)
                                    in zip(tcp_payload[::2], tcp_payload[1::2]))

    def dump(self):
        self.ether_header.dump(TCPPacket.num)
        self.ip_header.dump(TCPPacket.num)
        self.tcp_header.dump(TCPPacket.num)

        print_section_header("TCP PAYLOAD #{}".format(self.num))
        print(textwrap.fill(self.tcp_payload, 78))
        print_section_footer()


# format options structure; filled in when program options are parsed
cli_opts = {}


def parse_cli_opts():
    prog_args = sys.argv
    prog_protos = ['tcp', 'udp']
    prog_host = ['src', 'dst']

    try:
        pos = 1
        for i in range(1, len(prog_args)):
            if i < pos: continue

            arg = prog_args[i]

            if arg in prog_host and prog_args[i + 1] == "host":
                cli_opts[arg] = {"host": prog_args[i + 2].split(',')}
                pos += 3

            elif arg == "host":
                cli_opts["host"] = prog_args[i + 1].split(',')
                pos += 2

            elif arg in prog_protos and prog_args[i + 1] == "port":
                cli_opts[arg] = {"port": prog_args[i + 2].split(',')}
                pos += 3

            elif arg == "port":
                cli_opts["port"] = prog_args[i + 1].split(',')
                pos += 2

    except IndexError:
        pass


def main():
    sock = sniff_socket.create()

    # Start sniffing by checking packets in the loop
    try:
        while True:
            # Get a packet
            frame = sock.recv(4096)
            packet = TCPPacket(frame)

            # Only process IP packets
            if packet.ether_header.eth_type == EtherTypes.get("IPv4"):
                # Get the src host filter
                f_ip_src = cli_opts.get("host", []) + cli_opts.get("src", {'host': []}).get("host", [])
                # Get the dst host filter
                f_ip_dst = cli_opts.get("host", []) + cli_opts.get("dst", {'host': []}).get("host", [])
                # Get the port filter
                f_port = cli_opts.get("port", [])

                # Check if we want to capture from the src or dst
                ip_src = packet.ip_header.src_ip
                ip_dst = packet.ip_header.dst_ip

                if ip_src in f_ip_src or ip_dst in f_ip_dst:
                    proto = packet.ip_header.proto

                    if proto == TransportProtocols.get("TCP"):
                        # Get the TCP port filter
                        f_port += cli_opts.get("tcp", {'port': []}).get("port", [])

                        # Check if we want to capture from the src or dst port
                        tcp_src_port = str(packet.tcp_header.src_port)
                        tcp_dst_port = str(packet.tcp_header.dst_port)

                        if tcp_src_port in f_port or tcp_dst_port in f_port:
                            packet.dump()

                        else:
                            pass
                            # print "IGNORING TCP {}:{} -> {}:{}".format(
                            # ip_src, tcp_src_port, ip_dst, tcp_dst_port)

                    # elif proto == TransportProtocols.get("UDP"):
                    #     print("UDP")
                    #
                    # elif proto == TransportProtocols.get("ICMP"):
                    #     print("ICMP")
                    #
                    # else:
                    #     print("UNKNOWN ({})".format(proto))

                else:
                    pass
                    # print "IGNORING {} -> {}".format(ip_src, ip_dst)


    except (KeyboardInterrupt, SystemExit):
        pass

    finally:
        sniff_socket.close(sock)


if __name__ == "__main__":
    parse_cli_opts()
    main()
