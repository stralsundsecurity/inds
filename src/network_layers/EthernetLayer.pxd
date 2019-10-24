

# Struct with ethernet layer fields
cdef struct ethernet_layer_fields:

    # The *_start index points to the first byte of a field
    # The *_end index points to the next byte AFTER a field

    # Index of start and end of source mac address
    # The indexes are the first and last + 1 bytes
    unsigned int src_mac_start
    unsigned int src_mac_end
    # Source mac address
    unsigned long src_mac


    # Index of start and end of destination mac address
    # The indexes are the first and last + 1 bytes
    unsigned int dst_mac_start
    unsigned int dst_mac_end
    # Destination mac address
    unsigned long dst_mac


    # Index of start and end of next protocol field
    # The indexes are the first and last + 1 bytes
    unsigned int next_type_start
    unsigned int next_type_end
    # Next protocol identifier (e.g. 0x800 for IP)
    unsigned int next_type


    # Index of first byte after the header
    unsigned int end_of_header


cdef class EthernetLayer:

    """Wrapper class around the ethernet_layer_fields struct."""

    # Fields of the ethernet protocol
    cdef ethernet_layer_fields fields


# Function for parsing packet data of the ethernet protocol
cdef EthernetLayer parse_ethernet (bytearray packet_data, int start_of_layer)
