import cython

@cython.auto_pickle(True)
cdef class Packet:

    """
    Class that represents a parsed network packet

    """

    def __init__ (self, bytearray packet_data):
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

    # def __call__(self, *args, **kwargs):
    #     pass