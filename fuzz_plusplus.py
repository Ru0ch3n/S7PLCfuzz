# Author: Chai Ruochen From Xidian University, China.
# todo:
#  1.  频率更aggressive，达到PLC运行与通信能力上限                                                   √
#  2.  模块化多种Fuzz报文机制：手动变异规则、ML生成或变异
#  3.  完整的监视模块
#  4.  将s7comm回复存储，做特征值向量，尽可能往返回特征向量更少见的方向去变异！ 解决了覆盖率的问题。
#  5.  引入多线程和thread local变量机制                                                            √
#  6.  将TCP Stack从用户态改为使用内核态，故不再像前版本一样需要手动配置防火墙规则拦截Kernel堆栈发出的RST数据包 √
#  7.  支持多种模糊模式：读文件模式、实时变异/生成模式
#  8.  重构代码，主体部分更加简洁明朗                                                                √
#  9.  完善日志功能                                                                              √
#  10. 引入相似度计算（最小编辑距离）                                                                √
#================================================================================|<<<<<<<<<<<<|

import socket
import threading
import time
from multiprocessing import Process
import csv
from scapy.packet import Raw, Packet, fuzz
from scapy.supersocket import StreamSocket
from utils.utils import *

SRC = '192.168.0.241'
DST = '192.168.0.1'
DPORT = 102
FUZZ_LOG_CSV = open('fuzz_log.csv', 'a+')
FUZZ_LOG_WRITER = csv.writer(FUZZ_LOG_CSV)
MODE = 1

cotp_cr_packet = Packet(str2byte(simatic_200_smart_hello))
s7comm_setup_packet = Packet(str2byte(set_comm))
local = threading.local()

def test_proccess():
    local.counter = 0
    s = socket.socket()
    s.connect(("192.168.0.1", DPORT))
    ss = StreamSocket(s, Raw)    # supersocket.StreamSocket是Scapy对原生Socket的包装增强。使用Kernel级别TCP Stack，故不再像前用户态版本一样需要手动配置防火墙规则拦截Kernel堆栈发出的RST数据包，且大大提升测试效率
    try:
        ss.sr(cotp_cr_packet, verbose=0)
        ss.sr(s7comm_setup_packet, verbose=0)
        while local.counter < 10:
            fuzz_packet = Packet(str2byte(get_s7_fuzz_data()))
            ans= ss.sr1(fuzz(fuzz_packet), verbose=0)
            log_row = [byte2str(fuzz_packet.build()), byte2str(ans.build()), time.time(), MODE]
            FUZZ_LOG_WRITER.writerow(log_row)
            local.counter += 1
            print('send:{}\nrecv{}'.format(log_row[0], log_row[1]), end='\n************\n')
    except:
        s.close()

if __name__ == '__main__':
    round = 0
    for i in range(1000):
        p1 = Process(target=test_proccess)
        p2 =  Process(target=test_proccess)
        p3 =  Process(target=test_proccess)
        p1.start()
        p2.start()
        p3.start()

        time.sleep(4)

        p1.terminate()
        p2.terminate()
        p3.terminate()

        p1.join()
        p2.join()
        p3.join()

        p1.close()
        p2.close()
        p3.close()
























