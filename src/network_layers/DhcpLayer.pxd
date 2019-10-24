
# RFC 2131
#
# Also see https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
#
#
#     0               1               2               3
#     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
#    +---------------+---------------+---------------+---------------+
#    |                            xid (4)                            |
#    +-------------------------------+-------------------------------+
#    |           secs (2)            |           flags (2)           |
#    +-------------------------------+-------------------------------+
#    |                          ciaddr  (4)                          |
#    +---------------------------------------------------------------+
#    |                          yiaddr  (4)                          |
#    +---------------------------------------------------------------+
#    |                          siaddr  (4)                          |
#    +---------------------------------------------------------------+
#    |                          giaddr  (4)                          |
#    +---------------------------------------------------------------+
#    |                                                               |
#    |                          chaddr  (16)                         |
#    |                                                               |
#    |                                                               |
#    +---------------------------------------------------------------+
#    |                                                               |
#    |                          sname   (64)                         |
#    +---------------------------------------------------------------+
#    |                                                               |
#    |                          file    (128)                        |
#    +---------------------------------------------------------------+
#    |                                                               |
#    |                          options (variable)                   |
#    +---------------------------------------------------------------+


# FIELD      OCTETS       DESCRIPTION
#    -----      ------       -----------
#
#    op            1  Message op code / message type.
#                     1 = BOOTREQUEST, 2 = BOOTREPLY
#    htype         1  Hardware address type, see ARP section in "Assigned
#                     Numbers" RFC; e.g., '1' = 10mb ethernet.
#    hlen          1  Hardware address length (e.g.  '6' for 10mb
#                     ethernet).
#    hops          1  Client sets to zero, optionally used by relay agents
#                     when booting via a relay agent.
#    xid           4  Transaction ID, a random number chosen by the
#                     client, used by the client and server to associate
#                     messages and responses between a client and a
#                     server.
#    secs          2  Filled in by client, seconds elapsed since client
#                     began address acquisition or renewal process.
#    flags         2  Flags (see figure 2).
#    ciaddr        4  Client IP address; only filled in if client is in
#                     BOUND, RENEW or REBINDING state and can respond
#                     to ARP requests.
#    yiaddr        4  'your' (client) IP address.
#    siaddr        4  IP address of next server to use in bootstrap;
#                     returned in DHCPOFFER, DHCPACK by server.
#    giaddr        4  Relay agent IP address, used in booting via a
#                     relay agent.
#    chaddr       16  Client hardware address.
#    sname        64  Optional server host name, null terminated string.
#    file        128  Boot file name, null terminated string; "generic"
#                     name or null in DHCPDISCOVER, fully qualified
#                     directory-path name in DHCPOFFER.
#    options     var  Optional parameters field.  See the options
#                     documents for a list of defined options.

# implemented dhcp options
cdef enum DhcpOptionTypes:
    PAD = 0
    SUBNET_MASK = 1
    ROUTER = 3
    NAME_SERVER = 5
    DOMAIN_SERVER = 6
    HOSTNAME = 12
    DOMAIN_NAME = 15
    BROADCAST_ADDRESS = 28
    STATIC_ROUTE = 33
    TCP_KEEPALIVE_TIME = 38
    ADDRESS_REQUEST = 50
    ADDRESS_TIME = 51
    DHCP_MSG_TYPE = 53
    DHCP_SERVER_ID = 54
    PARAMETER_LIST = 55
    DHCP_MESSAGE = 56
    RENEWAL_TIME = 58
    REBINDING_TIME = 59
    CLIENT_ID = 61
    CLIENT_FQDN = 81
    END = 255
    NOT_YET_IMPLEMENTED = 256
    NULL_VALUE = 257


# dhcp message types (option 53)
cdef enum dhcp_option_msg_type_values:
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    FORCE_RENEW = 9

# bootp opcodes
cdef enum bootp_opcodes:
    BOOTP_REQUEST = 1
    BOOTP_REPLY = 2

# class of an dhcp option
cdef class dhcp_option:

    # The *_start index points to the first byte of a field
    # The *_end index points to the next byte AFTER a field

    # start and end index of option
    cdef unsigned int option_start
    cdef unsigned int option_end

    # dhcp option type
    cdef unsigned int option

    # length of option (second byte of option)
    cdef unsigned int option_length

    # option data (length equals option_length)
    cdef bytearray option_data


# Struct with dhcp layer fields
cdef struct dhcp_layer_fields:

    # The *_start index points to the first byte of a field
    # The *_end index points to the next byte AFTER a field

    # opcode of message (bootp)
    unsigned int opcode_start
    unsigned int opcode_end
    unsigned int opcode

    # Transaction ID
    unsigned int transaction_id_start
    unsigned int transaction_id_end
    unsigned int transaction_id

    # Client ip address
    unsigned int client_ip_addr_start
    unsigned int client_ip_addr_end
    unsigned int client_ip_addr

    # 'your' (client) ip address (see rfc2131)
    unsigned int your_ip_addr_start
    unsigned int your_ip_addr_end
    unsigned int your_ip_addr

    # client mac address
    # at the beginning of 16 byte field
    # the remaining 10 bytes padding are skipped
    unsigned int client_mac_addr_start
    unsigned int client_mac_addr_end
    unsigned long client_mac_addr

    # options field
    unsigned int options_start
    unsigned int options_end

    # Index of first byte after the header
    unsigned int end_of_header

cdef class DhcpLayer:

    """Wrapper class around the udp_layer_fields struct."""

    # Fields of the ethernet protocol
    cdef dhcp_layer_fields fields

    # dhcp options
    cdef list options


# Function for parsing packet data of the dhcp protocol
cdef DhcpLayer parse_dhcp (bytearray packet_data, int start_of_layer)
