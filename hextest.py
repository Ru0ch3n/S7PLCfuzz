import numpy as np

from utils.utils import *
from sklearn import datasets, cluster
a= []
a.append(minDistance("0300002102f080320700000031000c00040001120812910e00000081040a000000", "0300002102f080320700000040000c00040001120812b40100000081040a000000"))
a.append(minDistanceRatio("0300002102f080320700000031000c00040001120812910e00000081040a000000", "0300002102f080320700000040000c00040001120812b40100000081040a000000"))
a.append(minDistance("0300002102f080320700000050000c00040001120812810100000081040a000000", "0300002102f0803207000000c8000c00040001120812850100000081040a000000"))
a.append(minDistanceRatio("0300002102f080320700000050000c00040001120812810100000081040a000000", "0300002102f0803207000000c8000c00040001120812850100000081040a000000"))
a.append(minDistance("0300002102f080320700000028000c00040001120812a20100000081040a000000", "0300002102f0803207000000f5000c00040001120812820100000081040a000000"))
a.append(minDistanceRatio("0300002102f080320700000028000c00040001120812a20100000081040a000000", "0300002102f0803207000000f5000c00040001120812820100000081040a000000"))
a.append(minDistance("0300002102f080320700000081000c00040001120812920400000081040a000000", "0300002102f08032070000001d000c00040001120812920100000081040a000000"))
a.append(minDistanceRatio("0300002102f080320700000081000c00040001120812920400000081040a000000", "0300002102f08032070000001d000c00040001120812920100000081040a000000"))
a.append(minDistance("0300002102f080320700000081000c00040001120812920400000081040a000000", "0300002102f080320700000033000c00040001120812830300000085000a000000"))
a.append(minDistanceRatio("0300002102f080320700000081000c00040001120812920400000081040a000000", "0300002102f080320700000033000c00040001120812830300000085000a000000"))
a.append(minDistance("0300002102f080320700000004000c00040001120812a50100000081040a000000", "0300002102f080320700000033000c00040001120812830300000085000a000000"))
a.append(minDistanceRatio("0300002102f080320700000004000c00040001120812a50100000081040a000000", "0300002102f080320700000033000c00040001120812830300000085000a000000"))
a.append(minDistance("0300002102f080320700000004000c00040001120812a50100000081040a000000", "0300002102f080320700000033000c00040001120812830300000085000a000000"))
a.append(minDistanceRatio("0300002102f080320700000004000c00040001120812a50100000081040a000000", "0300002102f080320700000033000c00040001120812830300000085000a000000"))

example_ls = ['0300002102f080320700000031000c00040001120812910e00000081040a000000','0300002102f080320700000040000c00040001120812b40100000081040a000000',
              '0300002102f080320700000050000c00040001120812810100000081040a000000','0300002102f0803207000000c8000c00040001120812850100000081040a000000',
              '0300002102f0803207000000b1000c00040001120812b20100000081040a000000','0300002102f0803207000000f9000c00040001120812b30300000081040a000000',
              '0300002102f0803207000000ec000c00040001120812910100000081040a000000','0300002102f0803207000000d9000c00040001120812b20400000081040a000000',
              '0300002102f08032070000007d000c00040001120812950100000081040a000000','0300002102f0803207000000e8000c00040001120812b20100000081040a000000',
              '0300002102f08032070000003f000c00040001120812a50100000081040a000000', '0300002102f080320700000082000c00040001120812840100000081040a000000',
              '0300002102f0803207000000aa000c00040001120812b30100000081040a000000', '0300002102f080320700000023000c00040001120812870400000081040a000000']


# 获得块信息的诊断功能回复，写值的回复,列出块类型的回复，读值的回复
a1 = '0300002102f080320700000400000c000400011208128303000000d2090a000000'
a2 = '0300002502f080320700001800000c0008000112081283020100000000ff09000400012213'
a3 = '0300001602f0803203000013000002000100000501ff'
a4 = '0300001a02f0803203000014000002000500000401ff04000811'
a5 = '0300001802f0803203000032000002000300000503ff0303'
print(minDistanceRatio('ab', 'a'), end=' ')
print(minDistanceRatio('ab', 'cd'), end=' ')
print(minDistanceRatio('abc', 'ab'), end=' ')
print(minDistanceRatio('ab', 'ac'), end=' ')


print('xxxxxxxxxxx\n')
print(minDistanceRatio(a1, a2), end=' ')
print(minDistanceRatio(a1, a3), end=' ')
print(minDistanceRatio(a1, a4), end=' ')
print(minDistanceRatio(a1, a5), end='\n                   ')
print(minDistanceRatio(a2, a3), end=' ')
print(minDistanceRatio(a2, a4), end=' ')
print(minDistanceRatio(a2, a5), end='\n                                      ')
print(minDistanceRatio(a3, a4), end=' ')
print(minDistanceRatio(a3, a5), end='\n                                                         ')
print(minDistanceRatio(a4, a5))