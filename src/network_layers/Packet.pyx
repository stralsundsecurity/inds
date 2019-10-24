
cdef class Packet:

    """
    Class that represents a parsed network packet

    """

    def __cinit__ (self, bytearray packet_data):
        self.packet_data = packet_data

        # set all values to defaults
        self.ethernet_layer = None
        self.arp_layer = None
        self.ipv4_layer = None
        self.UNKNOWN_LAYER_3_PROTOCOL = False
        self.udp_layer = None
        self.UNKNOWN_LAYER_4_PROTOCOL = False
        self.dhcp_layer = None
        self.UNKNOWN_LAYER_5_PROTOCOL = False