import cython

from EthernetLayer cimport *
from utils.Utils cimport *
from ProtocolTypes cimport Protocols
from IPv4Layer cimport parse_ipv4


@cython.auto_pickle(True)
cdef class EthernetLayer:

    def __init__(self):
        # Default values for fields. 0 means empty (aka None).
        self.fields.src_mac_start = 0
        self.fields.src_mac_end = 0
        self.fields.src_mac = 0
        self.fields.dst_mac_start = 0
        self.fields.dst_mac_end = 0
        self.fields.dst_mac = 0
        self.fields.next_type_start = 0
        self.fields.next_type_end = 0
        self.fields.next_type = 0
        self.fields.end_of_header = 0



cdef EthernetLayer parse_ethernet (bytearray packet_data, int start_of_layer):

    """
    Function for parsing packet data of the ethernet protocol.
    
    :param packet_data Reference to a network packet
    :param start_of_layer Index of first byte of the layer of interest.
    
    :returns EthernetLayer object with parsed data.
    """

    cdef EthernetLayer layer = EthernetLayer()

    # length constants in bytes
    cdef unsigned int LENGTH_OF_MAC_ADDRESS_FIELD = 6
    cdef unsigned int LENGTH_OF_TYPE_FIELD = 2


    # destination mac
    layer.fields.dst_mac_start = start_of_layer
    layer.fields.dst_mac_end = layer.fields.dst_mac_start + LENGTH_OF_MAC_ADDRESS_FIELD
    layer.fields.dst_mac = convert_bytes_to_ulong(packet_data[layer.fields.dst_mac_start : layer.fields.dst_mac_end])

    # source mac
    layer.fields.src_mac_start = layer.fields.dst_mac_end
    layer.fields.src_mac_end = layer.fields.src_mac_start + LENGTH_OF_MAC_ADDRESS_FIELD
    layer.fields.src_mac = convert_bytes_to_ulong(packet_data[layer.fields.src_mac_start : layer.fields.src_mac_end])

    # next protocol
    layer.fields.next_type_start = layer.fields.src_mac_end
    layer.fields.next_type_end = layer.fields.next_type_start + LENGTH_OF_TYPE_FIELD
    layer.fields.next_type = convert_bytes_to_uint(packet_data[layer.fields.next_type_start : layer.fields.next_type_end])

    # end of header
    layer.fields.end_of_header = layer.fields.next_type_end



    # return parsed layer
    return layer


