import ctypes
import fcntl
import socket

# Internet Protocol packet [/usr/include/linux/if_ether.h]
ETH_P_IP = 0x0800

# Promiscuous mode to receive all packets [/usr/include/net.if.h]
IFF_PROMISC = 0x100

# Socket configuration controls [/usr/include/bits/ioctls.h]
SIOCGIFFLAGS = 0x8913   # Get flags
SIOCSIFFLAGS = 0x8914   # Set flags

# Interface from which to capture data
IF_NAME = "eth0".encode() # String in Unicode


# Model the C interface request structure since Python doesn't
# expose it [/usr/include/net/if.h].
class ifreq(ctypes.Structure):
    _fields_ = [
        # Interface name (i.e. eth0)
        ("ifr_ifrn", ctypes.c_char * 16),
        # Flags to apply
        ("ifr_flags", ctypes.c_short)
    ]


def __switch_promiscuous_mode(sock, switch):
    # Set up the ifreq
    ifr = ifreq()
    ifr.ifr_ifrn = IF_NAME

    # Get the current flags so we don't clobber them
    fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifr)

    if switch:                          # Turn on promiscuous mode
        ifr.ifr_flags |= IFF_PROMISC
    else:                               # Turn off promiscuous mode
        ifr.ifr_flags &= ~IFF_PROMISC

    # Set interface flags
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifr)


def create():
    # Create our raw socket
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Turn on promiscuous mode
    __switch_promiscuous_mode(sock, True)

    return sock

def close(sock):
    # Turn off promiscuous mode
    __switch_promiscuous_mode(sock, False)

    # Close the socket
    sock.close()

