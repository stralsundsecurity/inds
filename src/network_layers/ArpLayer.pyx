import cython

from EthernetLayer cimport *
from utils.Utils cimport *


@cython.auto_pickle(True)
cdef class ArpLayer:

    def __init__(self):
        # Default values for fields. 0 means empty (aka None).
        self.fields.opcode_start = 0
        self.fields.opcode_end = 0
        self.fields.opcode = 0
        self.fields.source_mac_start = 0
        self.fields.source_mac_end = 0
        self.fields.source_mac = 0
        self.fields.source_ip_start = 0
        self.fields.source_ip_end = 0
        self.fields.source_ip = 0
        self.fields.target_mac_start = 0
        self.fields.target_mac_end = 0
        self.fields.target_mac = 0
        self.fields.target_ip_start = 0
        self.fields.target_ip_end = 0
        self.fields.target_ip = 0
        self.fields.end_of_header = 0



cdef ArpLayer parse_arp (bytearray packet_data, int start_of_layer):

    """
    Function for parsing packet data of the arp protocol.
    
    :param packet_data Reference to a network packet
    :param start_of_layer Index of first byte of the layer of interest.
    
    :returns ArpLayer object with parsed data.
    """

    cdef ArpLayer layer = ArpLayer()

    cdef unsigned int LENGTH_OF_OPCODE_FIELD = 2
    cdef unsigned int LENGTH_OF_MAC_ADDRESS_FIELD = 6
    cdef unsigned int LENGTH_OF_IP_ADDRESS_FIELD = 4

    # opcode
    # 6 is offset from header start to opcode field
    layer.fields.opcode_start = start_of_layer + 6
    layer.fields.opcode_end = layer.fields.opcode_start + LENGTH_OF_OPCODE_FIELD
    layer.fields.opcode = convert_bytes_to_uint(packet_data[layer.fields.opcode_start : layer.fields.opcode_end])

    # source mac address
    layer.fields.source_mac_start = layer.fields.opcode_end
    layer.fields.source_mac_end = layer.fields.source_mac_start + LENGTH_OF_MAC_ADDRESS_FIELD
    layer.fields.source_mac = convert_bytes_to_ulong(packet_data[layer.fields.source_mac_start : layer.fields.source_mac_end])

    # source ip address
    layer.fields.source_ip_start = layer.fields.source_mac_end
    layer.fields.source_ip_end = layer.fields.source_ip_start + LENGTH_OF_IP_ADDRESS_FIELD
    layer.fields.source_ip = convert_bytes_to_uint(packet_data[layer.fields.source_ip_start : layer.fields.source_ip_end])

    # target mac address
    layer.fields.target_mac_start = layer.fields.source_ip_end
    layer.fields.target_mac_end = layer.fields.target_mac_start + LENGTH_OF_MAC_ADDRESS_FIELD
    layer.fields.target_mac = convert_bytes_to_ulong(packet_data[layer.fields.target_mac_start : layer.fields.target_mac_end])

    # target ip address
    layer.fields.target_ip_start = layer.fields.target_mac_end
    layer.fields.target_ip_end = layer.fields.target_ip_start + LENGTH_OF_IP_ADDRESS_FIELD
    layer.fields.target_ip = convert_bytes_to_uint(packet_data[layer.fields.target_ip_start : layer.fields.target_ip_end])

    # first byte of next layer
    layer.fields.end_of_header = layer.fields.target_ip_end


    # return parsed layer
    return layer


