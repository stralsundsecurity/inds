import multiprocessing
import socket

from NetworkIO cimport *
from utils.Parser cimport *
from utils.Parser import *
from utils.Utils import *
from utils.Utils cimport *

cdef void start_network_io(read_queue, write_queue, parsed_queue, unsigned int number_of_workers):
    """
    Creates a raw socket, that listens to all passing traffic and puts it into
    the read_queue. Simultaneously packets from the write_queue, if available, 
    are sent out.
    
    
    :param read_queue: Shared multiprocessing.Manager().Queue() for received packets
    :param write_queue: Shared multiprocessing.Manager().Queue() for packets to send
    :param parsed_queue: Shared multiprocessing.Manager().Queue() for parsed packets
    :param number_of_workers: Number of processes that parse incoming packets 
        (should be at least 4)
    :return: Void
    """


    # set up multiprocessing stuff
    pool = multiprocessing.Pool(processes=number_of_workers)
    manager = multiprocessing.Manager()

    # Start parser worker in separate processes.
    # Too many worker cause a too big management overhead (optimal value 4)
    for worker in range(number_of_workers):
        print("Starting worker {0:d}.".format(worker))
        pool.apply_async(parse_network_packet_parallel, (read_queue, parsed_queue, worker, ))

    # set up socket

                # socket.htons(0x0003) means "every packet"
                # see ETH_P_ALL	in https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
                # socket syntax description http://man7.org/linux/man-pages/man7/packet.7.html
                # socket.htons : search for function name at https://docs.python.org/3/library/socket.html
                # it just converts bytes to network-type order
                # The protocol parameter can be omitted, it will still work. I provide it just for integrity.

    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

                # search "AF_PACKET" here https://docs.python.org/3/library/socket.html
                # for the c description of the protocol field see http://man7.org/linux/man-pages/man7/packet.7.html
                # search for "struct sockaddr_ll"
                # it does not really matter, what value is provided in the "protocol" field of the tuple.
                # it works with every value. 0 is just a convenience.

    raw_socket.bind(("eth0", 0))
    raw_socket.setblocking(False)

    # set socket recv and send operation timeouts to 300 micro secs.
    # This time is more than enough to send or receive a normal packet.
    cdef double SOCKET_TIMEOUT = 0.000300
    raw_socket.settimeout(SOCKET_TIMEOUT)

    cdef bytes packet
    # While true try to receive a packet within the specified timeout time.
    # If no packet is received an exception is thrown, catched and passed.
    # If a packet is received it is put into the read_queue for further processing.
    # After that the write_queue is checked and all packets from that queue are sent.
    # This cycle (listening and sending) contains forever.

    # I know, that this type of "parallel data processing" is definitely not efficient.
    # A huge exception overhead is caused... BUT, it works and i spent lots of time to make it working.
    # Thus, it must be changed, but not jet.... :)
    while True:

        # set again listening timeout
        raw_socket.settimeout(SOCKET_TIMEOUT)

        # try to receive a packet
        try:
            packet = raw_socket.recv(9000)
            read_queue.put(packet)
            continue
        except:
            # ignore the exception
            pass

        # reset timeout
        raw_socket.settimeout(None)

        # if no packet available for reading
        # spoof mac addresses
        spoof_target_macs(raw_socket)


        # Check write_queue and if not empty, send all packets
        if (not write_queue.empty()):

            # unlock targets and send all elements
            unlock_target_and_send_data(write_queue, raw_socket, write_queue.qsize())




