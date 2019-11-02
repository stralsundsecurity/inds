
from network_layers.Packet cimport *

cdef dict dhcp_handler_states

cdef void change_subnet_mask_option(Packet packet, unsigned int new_mask)

cdef void change_default_gateway_option(Packet packet, unsigned int new_gateway)

cdef enum DhcpHandlerStates:
    INIT,
    ERROR,

    RENEWAL_CLIENT_SENT_REQUEST,
    RENEWAL_FORWARDED_REQUEST_TO_SERVER,
    RENEWAL_WAITING_FOR_ACK_FROM_SERVER,
    RENEWAL_MODIFYING_ACK_FROM_SERVER,
    RENEWAL_SENT_ACK_TO_CLIENT,

    INIT_CONNECTION_RECEIVED_DISCOVER,
    INIT_CONNECTION_WAITING_FOR_OFFER,
    INIT_CONNECTION_RECEIVED_OFFER,
    INIT_CONNECTION_WAITING_FOR_REQUEST,
    INIT_CONNECTION_RECEIVED_REQUEST,
    INIT_CONNECTION_SENT_ACK

cdef void start_spoofing_dhcp_server(macs_to_spoof_list)

cdef void stop_spoofing_dhcp_server(macs_to_spoof_list)

cdef class DhcpHandlerState:
    cdef DhcpHandlerStates state
    cdef Packet offer_packet

cdef void dhcp_packet_handler(Packet packet, DhcpHandlerState state, write_queue, macs_to_spoof_list, ip_to_mac_assignments)

cdef void dhcp_packet_handler_manager(Packet packet, write_queue, macs_to_spoof_list, ip_to_mac_assignments)

#cdef void packet_handler(write_queue, parsed_queue, unsigned int handler_nr, macs_to_spoof_list, ip_to_mac_assignments)

# cdef void start_incoming_packet_handler(write_queue, parsed_queue, unsigned int number_of_workers, macs_to_spoof_list, ip_to_mac_assignments)
