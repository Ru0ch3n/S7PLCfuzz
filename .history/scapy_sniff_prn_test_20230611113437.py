# 不使用伯克利包过滤规则来达到复杂的过滤规则
import scapy.plist
from scapy.all import *
import time

# 定义一个PacketList对象存储你想过滤出的packet
# Under developing
packetList = PacketList()


# 方法一 定义一个回调函数给prn
def package_prn_filter(package: Packet):
    if package.haslayer("TCP"):  # 这里写你的过滤逻辑，可以很简单，也可以很复杂
        packetList.append(package)  # 将package加入你的packetList

        """ 
        也可以考虑在这里实现，把想要的包实时地写入中间件
        dfs_client.save(package)
        ....
        """
    else:
        print("Not TCP")


sniffer = sniff(prn=package_prn_filter, timeout=10)

"""
方法二 定义lambda表达式
sniffer = sniff(prn = lambda x:packetList.append(x) if x.haslayer('TCP') and x.payload else print('Not TCP'), timeout= 10)
"""

print(sniffer.summary())
print("---------")
print(packetList.summary())
