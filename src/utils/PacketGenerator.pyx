
from PacketGenerator cimport *
from network_layers.ProtocolTypes cimport *

cdef bytearray generate_arp_packet(EthernetLayer ethernet_layer, ArpLayer arp_layer):

    """
    Generates a completely new arp packet from layers with data (no positions required)
    
    :param ethernet_layer: Ethernet layer data (no positions required).
    :param arp_layer: Arp layer data (no positions required).
    :return: Ready to send arp packet as bytearray.
    """

    cdef bytearray packet = bytearray()

    # ethernet layer
    packet.extend(convert_int_to_bytes(6, ethernet_layer.fields.dst_mac))
    packet.extend(convert_int_to_bytes(6, ethernet_layer.fields.src_mac))
    packet.extend(convert_int_to_bytes(2, Protocols.ARP))

    #arp layer
    packet.extend(convert_int_to_bytes(2, 0x1))
    packet.extend(convert_int_to_bytes(2, Protocols.IPv4))
    packet.extend(convert_int_to_bytes(1, 0x6))
    packet.extend(convert_int_to_bytes(1, 0x4))
    packet.extend(convert_int_to_bytes(2, arp_layer.fields.opcode))
    packet.extend(convert_int_to_bytes(6, arp_layer.fields.source_mac))
    packet.extend(convert_int_to_bytes(4, arp_layer.fields.source_ip))
    packet.extend(convert_int_to_bytes(6, arp_layer.fields.target_mac))
    packet.extend(convert_int_to_bytes(4, arp_layer.fields.target_ip))


    return packet

