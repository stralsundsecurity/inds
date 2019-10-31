import asyncio
import math
import multiprocessing
import socket

import binascii
from scapy.compat import raw
import json

from utils.NetworkIO cimport start_network_io
from utils.Parser cimport *
from network_layers.Packet cimport *
from utils.NetworkIO cimport *
from utils.Utils cimport MacsToSpoof as macs_to_spoof
from utils.Utils cimport IpToMacAssignments as ips_and_macs


cpdef test_parse(bytearray inp_packet):
    cdef Packet packet = parse_network_packet(inp_packet)

    # print information about all layers
    print("ethernet")
    print("ethernet layer == none: ", packet.ethernet_layer is None)
    print(json.dumps(packet.ethernet_layer.fields, indent=2))
    print("arp")
    print("arp layer == none: ", packet.arp_layer is None)
    print(json.dumps(packet.arp_layer.fields, indent=2))
    print("ipv4")
    print("ipv4 layer == none: ", packet.ipv4_layer is None)
    print(json.dumps(packet.ipv4_layer.fields, indent=2))
    print("No layer3 header: ", packet.UNKNOWN_LAYER_3_PROTOCOL)
    print("udp")
    print("udp layer == none: ", packet.udp_layer is None)
    print(json.dumps(packet.udp_layer.fields, indent=2))
    print("No layer4 header: ", packet.UNKNOWN_LAYER_4_PROTOCOL)
    print("dhcp")
    print("dhcp layer == none: ", packet.dhcp_layer is None)
    print(json.dumps(packet.dhcp_layer.fields, indent=2))
    if packet.dhcp_layer is not None:
        for opt in packet.dhcp_layer.options:
            if opt is None:
                break
            print("Option: ", (<dhcp_option>opt).option)
            print("Option data: ", binascii.hexlify((<dhcp_option>opt).option_data))
    print("No layer5 header: ", packet.UNKNOWN_LAYER_5_PROTOCOL)


cpdef test_network_io():

    pool_size = multiprocessing.cpu_count()

    manager = multiprocessing.Manager()
    read_queue = manager.Queue()
    parsed_queue = manager.Queue()
    write_queue = manager.Queue()

    macs_to_spoof.add(0xaaaaaaaaaabb)
    macs_to_spoof.add(0xbbbbbbbbbbcc)
    macs_to_spoof.add(0xccccccccccdd)
    print(macs_to_spoof)

    ips_and_macs[0xdddddddddddd] = 0xc0a86464
    ips_and_macs[0x84a6c88deea1] = 0xc0a864c8
    ips_and_macs[0xd42122234bb8] = 0xc0a864c9
    print(ips_and_macs)


    pack = "84a6c88deea1d42122234bb8080045000028aa4640003c067db4021751b1c0a802650050f023f910c71f233257c7501001626bff000037a2e17a008c"
    bytes_pack = bytearray(bytes.fromhex(pack))

    for i in range(10):
        write_queue.put(parse_network_packet(bytes_pack))

    start_network_io(read_queue, write_queue, parsed_queue, number_of_workers=pool_size)







