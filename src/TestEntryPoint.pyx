# import asyncio
# import math
# import multiprocessing
# import socket
#
# import binascii
# import time
#
# from scapy.compat import raw
# import json
#
# #from utils.NetworkIO cimport start_network_io
# # from attack.IncommingPacketHandler cimport *
# from attack.IncommingPacketHandler cimport *
# from utils.Parser cimport *
# from network_layers.Packet cimport *
# from utils.NetworkIO cimport *
#
#
#
# cpdef test_parse(bytearray inp_packet):
#     cdef Packet packet = parse_network_packet(inp_packet)
#
#     # print information about all layers
#     print("ethernet")
#     print("ethernet layer == none: ", packet.ethernet_layer is None)
#     print(json.dumps(packet.ethernet_layer.fields, indent=2))
#     print("arp")
#     print("arp layer == none: ", packet.arp_layer is None)
#     print(json.dumps(packet.arp_layer.fields, indent=2))
#     print("ipv4")
#     print("ipv4 layer == none: ", packet.ipv4_layer is None)
#     print(json.dumps(packet.ipv4_layer.fields, indent=2))
#     print("No layer3 header: ", packet.UNKNOWN_LAYER_3_PROTOCOL)
#     print("udp")
#     print("udp layer == none: ", packet.udp_layer is None)
#     print(json.dumps(packet.udp_layer.fields, indent=2))
#     print("No layer4 header: ", packet.UNKNOWN_LAYER_4_PROTOCOL)
#     print("dhcp")
#     print("dhcp layer == none: ", packet.dhcp_layer is None)
#     print(json.dumps(packet.dhcp_layer.fields, indent=2))
#     if packet.dhcp_layer is not None:
#         for opt in packet.dhcp_layer.options:
#             if opt is None:
#                 break
#             print("Option: ", (<dhcp_option>opt).option)
#             print("Option data: ", binascii.hexlify((<dhcp_option>opt).option_data))
#     print("No layer5 header: ", packet.UNKNOWN_LAYER_5_PROTOCOL)
#
#
# cpdef test_network_io():
#
#     cdef unsigned int pool_size = multiprocessing.cpu_count()
#
#     manager = multiprocessing.Manager()
#     read_queue = manager.Queue()
#     parsed_queue = manager.Queue()
#     write_queue = manager.Queue()
#     macs_to_spoof_list = manager.list()
#     ip_to_mac_assignments = manager.dict()
#
#     #macs_to_spoof_list.append(0xaaaaaaaaaabb)
#     #macs_to_spoof_list.append(0xbbbbbbbbbbcc)
#     #macs_to_spoof_list.append(0xccccccccccdd)
#     #print(macs_to_spoof_list)
#
#     #ip_to_mac_assignments[0xdddddddddddd] = 0xc0a86464
#     ip_to_mac_assignments[0x84a6c88deea1] = 0xc0a864c8
#     #ip_to_mac_assignments[0xd42122234bb8] = 0xc0a864c9
#     #ip_to_mac_assignments[0x0800274c6a9e] = 0xc0a80026 #PC2 (client)
#     #ip_to_mac_assignments[0x0800278bb41f] = 0xc0a80001 # PC1 (server)
#     ip_to_mac_assignments[0xffffffffffff] = 0xffffffff
#     print('ip to mac assignments', ip_to_mac_assignments)
#
#
#     # pack = "84a6c88deea1d42122234bb8080045000028aa4640003c067db4021751b1c0a802650050f023f910c71f233257c7501001626bff000037a2e17a008c"
#     # bytes_pack = bytearray(bytes.fromhex(pack))
#     #
#     # for i in range(10):
#     #     write_queue.put(parse_network_packet(bytes_pack))
#
#     #pool = multiprocessing.Pool(processes=1)
#     #pool.apply_async(start_incoming_packet_handler, (write_queue, parsed_queue, 2, macs_to_spoof_list, ip_to_mac_assignments, ))
#     # ps2 = pool.apply_async(start_network_io, (read_queue, write_queue, parsed_queue, macs_to_spoof_list, ip_to_mac_assignments, pool_size, ))
#
#     # while(ps1.ready() is not True and ps2.ready() is not True):
#     #     continue
#     # # ps1.get()
#     # # ps2.get()
#     # print("here")
#     # pool.close()
#     # print("now here")
#     # pool.join()
#     # print('amd mpw here')
#     #start_incoming_packet_handler(write_queue, parsed_queue, 2, macs_to_spoof_list, ip_to_mac_assignments)
#
#     # print('ggggg')
#     #
#     # # set up multiprocessing stuff
#     # pool = multiprocessing.Pool(processes=2)
#     # # manager = multiprocessing.Manager()
#     #
#     # # Start packet_handler worker in separate processes.
#     # # Too many worker cause a too big management overhead (optimal value 3)
#     #
#     # for handler in range(2):
#     #     print("Starting handler {0:d}.".format(handler))
#     #     pool.apply_async(packet_handler, (write_queue, parsed_queue, handler, macs_to_spoof_list, ip_to_mac_assignments, ))
#     #
#     # time.sleep(3)
#
#     #start_network_io(read_queue, write_queue, parsed_queue, macs_to_spoof_list, ip_to_mac_assignments, pool_size)
#
#
#
#
#
#
#
#
#
