import cython

from IPv4Layer cimport *
from utils.Utils cimport *
from ProtocolTypes cimport Protocols

@cython.auto_pickle(True)
cdef class IPv4Layer:

    def __init__(self):
        # Default values for fields. 0 means empty (aka None).
        self.fields.ihl = 0
        self.fields.total_length_start = 0
        self.fields.total_length_end = 0
        self.fields.total_length = 0
        self.fields.more_fragments_flag_set = False
        self.fields.next_type_start = 0
        self.fields.next_type_end = 0
        self.fields.next_type = 0
        self.fields.header_checksum_start = 0
        self.fields.header_checksum_end = 0
        self.fields.header_checksum = 0
        self.fields.source_ip_start = 0
        self.fields.source_ip_end = 0
        self.fields.source_ip = 0
        self.fields.dest_ip_start = 0
        self.fields.dest_ip_end = 0
        self.fields.dest_ip = 0
        self.fields.options_start = 0
        self.fields.options_end = 0
        self.fields.end_of_header = 0


cdef IPv4Layer parse_ipv4 (bytearray packet_data, int start_of_layer):

    """
    Function for parsing packet data of the ipv4 protocol.
    
    :param packet_data Reference to a network packet
    :param start_of_layer Index of first byte of the layer of interest.
    
    :returns IPv4Layer object with parsed data.
    """

    cdef IPv4Layer layer = IPv4Layer()

    # length constants in bytes
    cdef unsigned int LENGTH_OF_TOTAL_LENGTH_FIELD = 2
    cdef unsigned int LENGTH_OF_NEXT_TYPE_FIELD = 1
    cdef unsigned int LENGTH_OF_HEADER_CHECKSUM_FIELD = 2
    cdef unsigned int LENGTH_OF_SOURCE_IP_FIELD = 4
    cdef unsigned int LENGTH_OF_DESTINATION_IP_FIELD = 4

    # Internet header length extraction. Result in multiple of 4 Bytes
    cdef unsigned int temp_byte = packet_data[start_of_layer]
    cdef unsigned int ihl_mask = 0b1111
    layer.fields.ihl = temp_byte & ihl_mask

    # Total length
    layer.fields.total_length_start = start_of_layer + 2
    layer.fields.total_length_end = layer.fields.total_length_start + LENGTH_OF_TOTAL_LENGTH_FIELD
    layer.fields.total_length = convert_bytes_to_uint(packet_data[layer.fields.total_length_start : layer.fields.total_length_end])

    # next protocol type ("Protocol" field)
    layer.fields.next_type_start = layer.fields.total_length_end + 5
    layer.fields.next_type_end = layer.fields.next_type_start + LENGTH_OF_NEXT_TYPE_FIELD
    layer.fields.next_type = convert_bytes_to_uint(packet_data[layer.fields.next_type_start : layer.fields.next_type_end])

    # header checksum
    layer.fields.header_checksum_start = layer.fields.next_type_end
    layer.fields.header_checksum_end = layer.fields.header_checksum_start + LENGTH_OF_HEADER_CHECKSUM_FIELD
    layer.fields.header_checksum = convert_bytes_to_uint(packet_data[layer.fields.header_checksum_start : layer.fields.header_checksum_end])

    # Source ip
    layer.fields.source_ip_start = layer.fields.header_checksum_end
    layer.fields.source_ip_end = layer.fields.source_ip_start + LENGTH_OF_SOURCE_IP_FIELD
    layer.fields.source_ip = convert_bytes_to_uint(packet_data[layer.fields.source_ip_start : layer.fields.source_ip_end])

    # destination ip
    layer.fields.dest_ip_start = layer.fields.source_ip_end
    layer.fields.dest_ip_end = layer.fields.dest_ip_start + LENGTH_OF_DESTINATION_IP_FIELD
    layer.fields.dest_ip = convert_bytes_to_uint(packet_data[layer.fields.dest_ip_start : layer.fields.dest_ip_end])

    # end of header
    # 4 bytes * ihl
    layer.fields.end_of_header = start_of_layer + (4 * layer.fields.ihl)

    # more packets flag
    temp_byte = packet_data[start_of_layer + 6]
    cdef unsigned int more_fragments_mask = 0b00100000
    temp_byte = temp_byte & more_fragments_mask
    if temp_byte == 0b00100000 :
        layer.fields.more_fragments_flag_set = True
    else:
        layer.fields.more_fragments_flag_set = False


    # return function to parse the next protocol
    # custom switch statement...
    # return parsed layer and reference to a function for parsing of the next layer
#    if layer.next_type == Protocols.UDP:
#        return (layer, parse_udp)
    # NOT YET IMPLEMENTED
    # if layer.next_type == Protocols.TCP:
    #     return (layer, parse_tcp)


    # default return statement (no next protocol)
    return layer
