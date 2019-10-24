
from UdpLayer cimport *
from utils.Utils cimport *



cdef class UdpLayer:

    def __cinit__(self):
        # Default values for fields. 0 means empty (aka None).
        self.fields.source_port_start = 0
        self.fields.source_port_end = 0
        self.fields.source_port = 0
        self.fields.dest_port_start = 0
        self.fields.dest_port_end = 0
        self.fields.dest_port = 0
        self.fields.length_start = 0
        self.fields.length_end = 0
        self.fields.length = 0
        self.fields.checksum_start = 0
        self.fields.checksum_end = 0
        self.fields.checksum = 0
        self.fields.end_of_header = 0



cdef UdpLayer parse_udp (bytearray packet_data, int start_of_layer):

    """
    Function for parsing packet data of the udp protocol.
    
    :param packet_data Reference to a network packet
    :param start_of_layer Index of first byte of the layer of interest.
    
    :returns UdpLayer object with parsed data.
    """

    cdef UdpLayer layer = UdpLayer()

    # length constants in bytes
    # each field is 2 bytes long
    cdef unsigned int LENGTH_OF_FIELD = 2

    # source port
    layer.fields.source_port_start = start_of_layer
    layer.fields.source_port_end = layer.fields.source_port_start + LENGTH_OF_FIELD
    layer.fields.source_port = convert_bytes_to_uint(packet_data[layer.fields.source_port_start  : layer.fields.source_port_end])

    # destinatio port
    layer.fields.dest_port_start = layer.fields.source_port_end
    layer.fields.dest_port_end = layer.fields.dest_port_start + LENGTH_OF_FIELD
    layer.fields.dest_port = convert_bytes_to_uint(packet_data[layer.fields.dest_port_start  : layer.fields.dest_port_end])

    # packet length
    layer.fields.length_start = layer.fields.dest_port_end
    layer.fields.length_end = layer.fields.length_start + LENGTH_OF_FIELD
    layer.fields.length = convert_bytes_to_uint(packet_data[layer.fields.length_start  : layer.fields.length_end])

    # checksum
    layer.fields.checksum_start = layer.fields.length_end
    layer.fields.checksum_end = layer.fields.checksum_start + LENGTH_OF_FIELD
    layer.fields.checksum = convert_bytes_to_uint(packet_data[layer.fields.checksum_start  : layer.fields.checksum_end])

    # end of header
    layer.fields.end_of_header = layer.fields.checksum_end



    # return parsed layer
    return layer


