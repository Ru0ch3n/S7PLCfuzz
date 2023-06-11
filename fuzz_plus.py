# Author: Chai Ruochen
# todo:
#  1. 频率更aggressive
#  2. 模块化多种Fuzz报文机制：手动变异规则、ML生成或变异
#  3. 完整的监视模块
#  4. 将s7comm回复存储，做特征值向量，尽可能往返回特征向量更少见的方向去变异！ 解决了覆盖率的问题。
#  5. 引入多线程和thread local变量机制                                                            √
#  6. 将TCP Stack从用户态改为使用内核态，故不再像前版本一样需要手动配置防火墙规则拦截Kernel堆栈发出的RST数据包 √
#  7. 支持多种模糊模式：读文件模式、实时变异/生成模式
#  8. 重构代码，主体部分更加简洁明朗                                                                √
# Under developing
import socket
import threading
import time

from scapy.layers.inet import TCP
from scapy.packet import Raw, Packet
from scapy.supersocket import StreamSocket
from utils.utils import *


# 全局变量
src = "192.168.0.241"
dst = "192.168.0.1"
dport = 102
fuzz_num = 0

hello = "03000016" + "11e00000001200c1020100c2020102c0010a"
simatic_200_smart_hello = "03000016" + "11e00000000100c0010ac1020100c2020200"
set_comm = "03000019" + "02f080" + "32010000000000080000f0000001000101e0"
message_str = "0300002102f080320700000100000800080001120411440100ff09000400110000"
ROSCTR_dict = {0: "01", 1: "07"}
userdata_dict = {0: "01", 1: "02", 2: "03", 3: "07"}
Group_funciton_dict = {
    1: {0: "01", 1: "02", 2: "0c", 3: "0e", 4: "0f", 5: "10", 6: "13"},
    2: {0: "01", 1: "04"},
    3: {0: "01", 1: "02", 2: "03"},
    4: {0: "01", 1: "02", 2: "03"},
    5: {0: "01"},
    6: {0: ""},
    7: {0: "01", 1: "02", 2: "03", 3: "04"},
}
Return_code_dict = {
    0: "00",
    1: "01",
    2: "03",
    3: "05",
    4: "06",
    5: "07",
    6: "0a",
    7: "ff",
}
Transport_size_dict = {0: "00", 1: "03", 2: "04", 3: "05", 4: "06", 5: "07", 6: "09"}
testdata_str = "0300002102f080320700000100000800080001120411440100ff09000400110000"
""" S/SA/A/PA/R"""
flags = {0: 2, 1: 18, 2: 16, 3: 24, 4: 4}


cotp_cr_packet = Packet(str2byte(simatic_200_smart_hello))
s7comm_setup_packet = Packet(str2byte(set_comm))

# thread local变量机制
local = threading.local()


def get_s7_fuzz_data():
    """Create TPKT"""

    TPKT_Version = "03"
    TPKT_Reserved = "00"
    # TPKT_Length = randomString(1).zfill(2) + randomString(1).zfill(2)
    TPKT_Length = ((hex(random.randint(58, 60)))[2:]).zfill(4)
    TPKT = TPKT_Version + TPKT_Reserved + TPKT_Length

    """ Create COTP """

    COTP_Length = "02"
    # COTP_PDU_Type = ((hex(random.randint(0, 16)))[2:]) + '0'
    COTP_PDU_Type = "f0"
    COTP_Last_data_unit = "80"
    COTP = COTP_Length + COTP_PDU_Type + COTP_Last_data_unit

    """ S7-Head"""

    Protocol_ID = "32"
    ROSCTR = ROSCTR_dict[random.randint(0, 1)]
    Redundancy_Identification = "0000"
    Protocol_Data_Unit_Reference = generate_random_string(2).zfill(4)
    Parameter_Length = "0008"
    Head_Data_Length = (hex(int(((int(TPKT_Length, 16)) * 2 - 14 - 36) / 2))[2:]).zfill(
        4
    )
    Header = (
        Protocol_ID
        + ROSCTR
        + Redundancy_Identification
        + Protocol_Data_Unit_Reference
        + Parameter_Length
        + Head_Data_Length
    )

    """ S7-Parameter """
    Parameter_head = "000112"
    Parameter_length = "04"
    Parameter_Request = generate_random_string(1).zfill(2)
    # Parameter_Type = str(random.randint(0, 16))
    Parameter_Type = (generate_random_string(1))[0]
    Parameter_FunctionGroup = random.randint(1, 7)
    Parameter_subfunciton = random.choice(Group_funciton_dict[Parameter_FunctionGroup])
    Parameter_FunctionGroup = str(Parameter_FunctionGroup)
    Parameter_Sequence_number = generate_random_string(1).zfill(2)
    Parameter = (
        Parameter_head
        + Parameter_length
        + Parameter_Request
        + Parameter_Type
        + Parameter_FunctionGroup
        + str(Parameter_subfunciton)
        + Parameter_Sequence_number
    )

    """ S7-Data """
    Data_ReturnCode = Return_code_dict[random.randint(0, 7)]
    Data_Transport_size = Transport_size_dict[random.randint(0, 6)]
    Data_Length = ((int(Head_Data_Length, 16) * 2) - 8) / 2
    Data_Data = ""
    Data_Data = generate_random_string(int(Data_Length)).zfill(int(Data_Length) * 2)
    Data_Length = (hex(int(Data_Length)))[2:].zfill(4)
    Data = Data_ReturnCode + Data_Transport_size + Data_Length + Data_Data

    """ the fuzz packet """
    fuzz_pkt = TPKT + COTP + Header + Parameter + Data
    return fuzz_pkt


def test_thread():
    global fuzz_num
    local.counter = 0
    s = socket.socket()
    s.connect(("192.168.0.1", 102))
    ss = StreamSocket(
        s, Raw
    )  # supersocket.StreamSocket是Scapy对原生Socket的包装增强。使用Kernel级别TCP Stack，故不再像前用户态版本一样需要手动配置防火墙规则拦截Kernel堆栈发出的RST数据包，且大大提升测试效率
    try:
        ss.sr(cotp_cr_packet, verbose=0)
        ss.sr(s7comm_setup_packet, verbose=0)
        while local.counter < 3:
            fuzz_packet = Packet(str2byte(get_s7_fuzz_data()))
            ans = ss.sr1(fuzz_packet, verbose=0)
            fuzz_num += 1
            local.counter += 1
        s.shutdown()  # 要用shutdown，不然不会正常释放连接，导致PLC TCP连接资源被耗尽
    except:
        s.close()


if __name__ == "__main__":
    round = 0
    while True:
        t1 = threading.Thread(target=test_thread)
        t2 = threading.Thread(target=test_thread)
        t1.start()
        time.sleep(2)
        try:
            stop_thread(t1)
        except:
            print("tcp_round: {} fuzz_num:{}".format(round, fuzz_num))
        round += 1
        if round % 10 == 0:
            time.sleep(1)
