from time import perf_counter

from TestEntryPoint import *


data = "ffffffffffff00a0573a22e7080045000157dc7e00003c1197170a000001ffffffff004300440143c71002010600a2f6846300000000000000000a00aea20000000000000000d4c9efe2227d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006382536335010536040a0000013d0701d4c9efe2227d0104ffff000003040a00000106040a0000010f06696e7465726e1c040a00ffff2604000000003304000075303a0400003a983b04000057e4ff"
data = bytearray.fromhex(data)


t1_start = perf_counter()

for i in range(0, 1000000):

    test_parse(data)

t1_stop = perf_counter()
print("Elapsed time: ", t1_stop - t1_start)
print("Time for one run in micsro sec: ", (t1_stop - t1_start) / 1000000 * 1000000)