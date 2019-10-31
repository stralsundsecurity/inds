import concurrent
import math
import multiprocessing
import select
import socket
from time import perf_counter, time

from TestEntryPoint import *

from network_layers.Packet import Packet

test_network_io()

