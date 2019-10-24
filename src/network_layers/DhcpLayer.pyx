
from DhcpLayer cimport *
from utils.Utils cimport *


cdef class DhcpLayer:

    def __cinit__(self):
        # Default values for fields. 0 means empty (aka None).
        self.fields.opcode_start = 0
        self.fields.opcode_end = 0
        self.fields.opcode = 0
        self.fields.transaction_id_start = 0
        self.fields.transaction_id_end = 0
        self.fields.transaction_id = 0
        self.fields.client_ip_addr_start = 0
        self.fields.client_ip_addr_end = 0
        self.fields.client_ip_addr = 0
        self.fields.your_ip_addr_start = 0
        self.fields.your_ip_addr_end = 0
        self.fields.your_ip_addr = 0
        self.fields.client_mac_addr_start = 0
        self.fields.client_mac_addr_end = 0
        self.fields.client_mac_addr = 0
        self.fields.options_start = 0
        self.fields.options_end = 0
        # number of supported options per packet is 50 (should be enough for most cases)
        # because i don't want to use dynamic data structures
        # init options list with empty values
        self.options = [None]*50
        #TODO debug
        #self.options = list()
        self.fields.end_of_header = 0


cdef class dhcp_option:

    def __cinit__(self):
        # set all attributes to init values
        self.option_start = 0
        self.option_end = 0
        self.option = 0
        self.option_length = 0
        self.option_data = bytearray()


cdef DhcpLayer parse_dhcp (bytearray packet_data, int start_of_layer):

    """
    Function for parsing packet data of the dhcp protocol.
    Checks if provided header really is a dhcp header (by checking the magic cookie).
    If valid dhcp data provided --> parse; else throw exception
    
    :param packet_data Reference to a network packet
    :param start_of_layer Index of first byte of the layer of interest.
    
    :returns DhcpLayer object with parsed data.
    """

    # magic number (dhcp magic cookie) that indicates the dhcp header
    cdef unsigned int DHCP_MAGIC_COOKIE_VALUE = 0x63825363
    # magic cookie offset in packet
    cdef unsigned int DHCP_MAGIC_COOKIE_OFFSET = 236
    cdef unsigned int DHCP_MAGIC_COOKIE_LENGTH = 4


    # check if dhcp header exists
    # if no header found - raise exception
    if len(packet_data) < start_of_layer + DHCP_MAGIC_COOKIE_OFFSET + DHCP_MAGIC_COOKIE_LENGTH:
        raise Exception("No dhcp layer found.")

    if convert_bytes_to_uint(packet_data[start_of_layer + DHCP_MAGIC_COOKIE_OFFSET \
       : start_of_layer + DHCP_MAGIC_COOKIE_OFFSET + DHCP_MAGIC_COOKIE_LENGTH]) != DHCP_MAGIC_COOKIE_VALUE:
        raise Exception("No dhcp layer found.")

    # found dhcp header
    cdef DhcpLayer layer = DhcpLayer()

    #some constants
    cdef unsigned int LENGTH_OF_TRANSACTION_ID_FIELD = 4
    cdef unsigned int LENGTH_OF_CLIENT_IP_ADDR_FIELD = 4
    cdef unsigned int LENGTH_OF_YOUR_IP_ADDR_FIELD = 4
    cdef unsigned int LENGTH_OF_CLIENT_MAC_ADDR_FIELD = 6

    # bootp opcode
    layer.fields.opcode_start = start_of_layer
    layer.fields.opcode_end = layer.fields.opcode_start + 1
    layer.fields.opcode = convert_bytes_to_uint(packet_data[layer.fields.opcode_start : layer.fields.opcode_end])

    # transaction id
    layer.fields.transaction_id_start = layer.fields.opcode_end + 3
    layer.fields.transaction_id_end = layer.fields.transaction_id_start + LENGTH_OF_TRANSACTION_ID_FIELD
    layer.fields.transaction_id = convert_bytes_to_uint(packet_data[layer.fields.transaction_id_start : layer.fields.transaction_id_end])

    # client ip address
    layer.fields.client_ip_addr_start = layer.fields.transaction_id_end + 4
    layer.fields.client_ip_addr_end = layer.fields.client_ip_addr_start + LENGTH_OF_CLIENT_IP_ADDR_FIELD
    layer.fields.client_ip_addr = convert_bytes_to_uint(packet_data[layer.fields.client_ip_addr_start : layer.fields.client_ip_addr_end])

    # 'your' ip address
    layer.fields.your_ip_addr_start = layer.fields.client_ip_addr_end
    layer.fields.your_ip_addr_end = layer.fields.your_ip_addr_start + LENGTH_OF_YOUR_IP_ADDR_FIELD
    layer.fields.your_ip_addr = convert_bytes_to_uint(packet_data[layer.fields.your_ip_addr_start : layer.fields.your_ip_addr_end])

    # client mac address (in the first 6 bytes of the 16 bytes long field)
    layer.fields.client_mac_addr_start = layer.fields.your_ip_addr_end + 8
    layer.fields.client_mac_addr_end = layer.fields.client_mac_addr_start + LENGTH_OF_CLIENT_MAC_ADDR_FIELD
    layer.fields.client_mac_addr = convert_bytes_to_ulong(packet_data[layer.fields.client_mac_addr_start : layer.fields.client_mac_addr_end])



    cdef unsigned int next_option_start = 0
    cdef unsigned int option_index = 0
    cdef dhcp_option option = dhcp_option()

    # extract all dhcp options
    # get first option
    # + 2 for option byte and option_length byte
    if len(packet_data) < start_of_layer + DHCP_MAGIC_COOKIE_OFFSET + DHCP_MAGIC_COOKIE_LENGTH + 2:
        # no options found --> return parsed bootp layer
        return layer

    # option section start
    layer.fields.options_start = start_of_layer + DHCP_MAGIC_COOKIE_OFFSET + DHCP_MAGIC_COOKIE_LENGTH


    option.option_start = (start_of_layer + DHCP_MAGIC_COOKIE_OFFSET + DHCP_MAGIC_COOKIE_LENGTH)
    option.option = packet_data[option.option_start]

    # check if option not DhcpOptionTypes.END
    if option.option == DhcpOptionTypes.END:
        return layer

    option.option_length = packet_data[option.option_start + 1]
    # + 2 for option byte and option_length byte
    option.option_end = option.option_start + option.option_length + 2



    option.option_data = packet_data[option.option_start + 2 : option.option_end]
    # add option to options list
    #TODO debug
    layer.options[option_index] = option
    #layer.options.append(option)
    next_option_start = option.option_end

    # extract all options
    while packet_data[next_option_start] != DhcpOptionTypes.END:
        option_index += 1

        # if too many options
        if (option_index >= 50) :
            return layer

        option = dhcp_option()
        option.option_start = next_option_start
        option.option = packet_data[option.option_start]
        option.option_length = packet_data[option.option_start + 1]
        option.option_end = option.option_start + option.option_length + 2
        option.option_data = packet_data[option.option_start + 2 : option.option_end]

        # add option to options list
        #TODO debug
        layer.options[option_index] = option
        #layer.options.append(option)

        #TODO debug
        #print(option.option)

        next_option_start = option.option_end

    # end of header right after option END (may not be correct due to padding)
    layer.fields.end_of_header = next_option_start + 1

    # end of options section
    layer.fields.options_end = next_option_start + 1



    # return parsed layer
    return layer


