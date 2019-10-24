
#     0               1               2               3
#     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |Version|  IHL  |Type of Service|          Total Length         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |         Identification        |Flags|      Fragment Offset    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |  Time to Live |    Protocol   |         Header Checksum       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                       Source Address                          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Destination Address                        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    Options                    |    Padding    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Struct with ipv4 layer fields
cdef struct ipv4_layer_fields:

    # The *_start index points to the first byte of a field
    # The *_end index points to the next byte AFTER a field

    # Internet header length (multiple of 4 Bytes). Max value 1111 -> header is 60 Bytes long
    unsigned int ihl

    # Total length of packet
    unsigned int total_length_start
    unsigned int total_length_end
    unsigned int total_length

    # More Fragments flag (indicates fragmented packet)
    bint more_fragments_flag_set

    # Type of next protocol
    unsigned int next_type_start
    unsigned int next_type_end
    unsigned int next_type

    # Header checksum
    unsigned int header_checksum_start
    unsigned int header_checksum_end
    unsigned int header_checksum

    # Source IP
    unsigned int source_ip_start
    unsigned int source_ip_end
    unsigned int source_ip

    # Destination IP
    unsigned int dest_ip_start
    unsigned int dest_ip_end
    unsigned int dest_ip

    # Options fields
    unsigned int options_start
    unsigned int options_end

    # First byte after the header
    unsigned int end_of_header


cdef class IPv4Layer:

    """Wrapper class around the ipv4_layer_fields struct."""

    # Fields of the ipv4 protocol
    cdef ipv4_layer_fields fields


# Function for parsing packet data of the ipv4 protocol
cdef IPv4Layer parse_ipv4 (bytearray packet_data, int start_of_layer)