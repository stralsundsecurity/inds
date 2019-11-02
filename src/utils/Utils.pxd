
from network_layers.Packet cimport *

cdef unsigned int convert_bytes_to_uint(bytearray value)

cdef unsigned long convert_bytes_to_ulong(bytearray value)

cdef bytearray convert_int_to_bytes(unsigned int length, unsigned long value)

cdef bytearray generate_arp_unlock_packet(unsigned long mac_address, ip_to_mac_assignments)

cdef void unlock_target_and_send_data(write_queue, raw_socket, buffer_size, ip_to_mac_assignments)


cdef void spoof_target_macs(raw_socket, macs_to_spoof_list)

cdef unsigned int calculate_udp_checksum(Packet packet)