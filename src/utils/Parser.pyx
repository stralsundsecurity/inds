import traceback

from network_layers.EthernetLayer cimport *
from network_layers.IPv4Layer cimport *
from network_layers.ArpLayer cimport *
from network_layers.UdpLayer cimport *
from network_layers.DhcpLayer cimport *
from network_layers.ProtocolTypes cimport *
from Parser cimport *


#                  Parse order / result
#
#                        Ethernet
#                           +
#                           |
#         +------------------------------------+
#         |                 |                  |
#         v                 v                  v
#        Arp              IPv4              UNKNOWN
#                           +
#                          |
#                 +---------+---------+
#                 |                   |
#                 v                   v
#                Udp               UNKNOWN
#                 +
#                 |
#           +-----+-----+
#           |           |
#           v           v
#          Dhcp      UNKNOWN


cdef unsigned int ETHERNET_HEADER_LENGTH = 14
cdef unsigned int ARP_HEADER_LENGTH = 28
cdef unsigned int IPV4_MIN_HEADER_LENGTH = 20
cdef unsigned int UDP_HEADER_LENGTH = 8
# including magic cookie
cdef unsigned int DHCP_HEADER_LENGTH = 240

cdef Packet parse_network_packet(bytearray packet_bytes):

    """
    Parses a raw packet (packet_bytes) to a Packet object, that contains information about different layers 
    of the packet
    
    :param packet_bytes: A raw Ethernet network packet
    :return: An object with different network layers
    
    """

    cdef Packet packet = Packet(packet_bytes)

    # check if there could be an ethernet header
    if len(packet_bytes) < ETHERNET_HEADER_LENGTH :
        raise Exception("Provided packet is too small. It can not contain an Ethernet header.")

    # ethernet header can be in packet
    packet.ethernet_layer = parse_ethernet(packet_bytes, 0)

    # check if next protocol supported
    # arp
    if packet.ethernet_layer.fields.next_type == Protocols.ARP:

        # check if there could be an arp header
        if len(packet_bytes[packet.ethernet_layer.fields.end_of_header:]) < ARP_HEADER_LENGTH:
            raise Exception("Next protocol type arp, but remaining packet to small.")

        packet.arp_layer = parse_arp(packet_bytes, packet.ethernet_layer.fields.end_of_header)
        return packet
    # ipv4
    if packet.ethernet_layer.fields.next_type == Protocols.IPv4:

        # check if there could be an ipv4 header
        if len(packet_bytes[packet.ethernet_layer.fields.end_of_header:]) < IPV4_MIN_HEADER_LENGTH:
            raise Exception("Next protocol type ipv4, but remaining packet to small.")

        packet.ipv4_layer = parse_ipv4(packet_bytes, packet.ethernet_layer.fields.end_of_header)

        # check if next protocol supported
        #udp
        if packet.ipv4_layer.fields.next_type == Protocols.UDP:

            # check if there could be an udp header
            if len(packet_bytes[packet.ipv4_layer.fields.end_of_header:]) < UDP_HEADER_LENGTH:
                raise Exception("Next protocol type udp, but remaining packet to small")

            packet.udp_layer = parse_udp(packet_bytes, packet.ipv4_layer.fields.end_of_header)

            # check if next protocol supported
            # dhcp
            # check if there could be a dhcp header
            if len(packet_bytes[packet.udp_layer.fields.end_of_header:]) < DHCP_HEADER_LENGTH:
                # if no dhcp header
                packet.UNKNOWN_LAYER_5_PROTOCOL = True
                return packet

            # if could be a dhcp layer
            try:
                packet.dhcp_layer = parse_dhcp(packet_bytes, packet.udp_layer.fields.end_of_header)
                return packet
            except Exception as e:
                # no dhcp layer found
                #traceback.print_exc()
                packet.UNKNOWN_LAYER_5_PROTOCOL = True
                return packet


        # if no supported layer 4 protocol found
        packet.UNKNOWN_LAYER_4_PROTOCOL = True
        packet.UNKNOWN_LAYER_5_PROTOCOL = True
        return packet

    # no supported layer 3 protocol found
    packet.UNKNOWN_LAYER_3_PROTOCOL = True
    packet.UNKNOWN_LAYER_4_PROTOCOL = True
    packet.UNKNOWN_LAYER_5_PROTOCOL = True

    return packet











