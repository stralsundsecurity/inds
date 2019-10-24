
# enum with major protocol types
cdef enum Protocols:
    IPv4 = 0x0800
    # not yet implemented
    IPv6 = 0x86DD
    ARP = 0x0806
    # not yet implemented
    TCP = 0x06
    UDP = 0x11