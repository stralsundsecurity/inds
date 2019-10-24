import binascii
import json

from utils.Parser cimport *
from network_layers.Packet cimport *

cpdef test_parse(bytearray inp_packet):
    cdef Packet packet = parse_network_packet(inp_packet)

    # # print information about all layers
    # print("ethernet")
    # print("ethernet layer == none: ", packet.ethernet_layer is None)
    # print(json.dumps(packet.ethernet_layer.fields, indent=2))
    # print("arp")
    # print("arp layer == none: ", packet.arp_layer is None)
    # print(json.dumps(packet.arp_layer.fields, indent=2))
    # print("ipv4")
    # print("ipv4 layer == none: ", packet.ipv4_layer is None)
    # print(json.dumps(packet.ipv4_layer.fields, indent=2))
    # print("No layer3 header: ", packet.UNKNOWN_LAYER_3_PROTOCOL)
    # print("udp")
    # print("udp layer == none: ", packet.udp_layer is None)
    # print(json.dumps(packet.udp_layer.fields, indent=2))
    # print("No layer4 header: ", packet.UNKNOWN_LAYER_4_PROTOCOL)
    # print("dhcp")
    # print("dhcp layer == none: ", packet.dhcp_layer is None)
    # print(json.dumps(packet.dhcp_layer.fields, indent=2))
    # if packet.dhcp_layer is not None:
    #     for opt in packet.dhcp_layer.options:
    #         if opt is None:
    #             break
    #         print("Option: ", (<dhcp_option>opt).option)
    #         print("Option data: ", binascii.hexlify((<dhcp_option>opt).option_data))
    # print("No layer5 header: ", packet.UNKNOWN_LAYER_5_PROTOCOL)