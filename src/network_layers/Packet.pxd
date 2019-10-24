
from network_layers.EthernetLayer cimport *
from network_layers.IPv4Layer cimport *
from network_layers.ArpLayer cimport *
from network_layers.UdpLayer cimport *
from network_layers.DhcpLayer cimport *
from network_layers.ProtocolTypes cimport *

cdef class Packet:

    # bytes of a packet
    cdef bytearray packet_data

    # The layer numbers may not be exact.
    # They are used just as a dummy flag

    # Reference to the ethernet layer
    cdef EthernetLayer ethernet_layer

    # Reference to the arp layer
    cdef ArpLayer arp_layer
    # Reference to the ipv4 layer
    cdef IPv4Layer ipv4_layer
    cdef bint UNKNOWN_LAYER_3_PROTOCOL

    # Reference to the udp layer
    cdef UdpLayer udp_layer
    cdef bint UNKNOWN_LAYER_4_PROTOCOL

    # Reference to the dhcp layer
    cdef DhcpLayer dhcp_layer
    cdef bint UNKNOWN_LAYER_5_PROTOCOL
