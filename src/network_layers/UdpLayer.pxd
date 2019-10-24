
#  0               1               2               3
#  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
# -----------------------------------------------------------------
# |          Source Port          |        Destination Port       |
# -----------------------------------------------------------------
# |             Length            |            Checksum           |
# -----------------------------------------------------------------


# Struct with udp layer fields
cdef struct udp_layer_fields:

    # The *_start index points to the first byte of a field
    # The *_end index points to the next byte AFTER a field

    # Source Port number
    unsigned int source_port_start
    unsigned int source_port_end
    unsigned int source_port

    # Destination Port number
    unsigned int dest_port_start
    unsigned int dest_port_end
    unsigned int dest_port

    # Packet length
    unsigned int length_start
    unsigned int length_end
    unsigned int length

    # Checksum
    unsigned int checksum_start
    unsigned int checksum_end
    unsigned int checksum

    # Index of first byte after the header
    unsigned int end_of_header


cdef class UdpLayer:

    """Wrapper class around the udp_layer_fields struct."""

    # Fields of the ethernet protocol
    cdef udp_layer_fields fields


# Function for parsing packet data of the ethernet protocol
cdef UdpLayer parse_udp (bytearray packet_data, int start_of_layer)
