

# Struct with arp layer fields
import cython


cdef struct arp_layer_fields:

    # The *_start index points to the first byte of a field
    # The *_end index points to the next byte AFTER a field

    # Arp opcode
    unsigned int opcode_start
    unsigned int opcode_end
    unsigned int opcode

    # Source mac address
    unsigned long source_mac_start
    unsigned long source_mac_end
    unsigned long source_mac

    # Source ip address
    unsigned int source_ip_start
    unsigned int source_ip_end
    unsigned int source_ip

    # Target mac address
    unsigned long target_mac_start
    unsigned long target_mac_end
    unsigned long target_mac

    # Target ip address
    unsigned int target_ip_start
    unsigned int target_ip_end
    unsigned int target_ip

    # Index of first byte after the header
    unsigned int end_of_header


@cython.auto_pickle(True)
cdef class ArpLayer:

    """Wrapper class around the arp_layer_fields struct."""

    # Fields of the ethernet protocol
    cdef arp_layer_fields fields


# Function for parsing packet data of the arp protocol
cdef ArpLayer parse_arp (bytearray packet_data, int start_of_layer)
