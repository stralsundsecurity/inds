
from network_layers.ArpLayer cimport *
from network_layers.EthernetLayer cimport *
from utils.Utils cimport *

cdef bytearray generate_arp_packet(EthernetLayer ethernet_layer, ArpLayer arp_layer)