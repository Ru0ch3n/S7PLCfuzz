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
# ================================================================================|<<<<<<<<<<<<|
# Under developing
import pickle
import socket
import threading
import time
from multiprocessing import Process
import csv
from scapy.packet import Raw, Packet, fuzz
from scapy.supersocket import StreamSocket
from utils.utils import *
from treelib import Tree, Node

SRC = "192.168.0.241"
DST = "192.168.0.1"
DPORT = 102
FUZZ_LOG_CSV = open("fuzz_log.csv", "a+")
FUZZ_LOG_WRITER = csv.writer(FUZZ_LOG_CSV)
MODE = 1

cotp_cr_packet = Packet(str2byte(simatic_200_smart_hello))
s7comm_setup_packet = Packet(str2byte(set_comm))
local = threading.local()

smart_fuzzing_tree = Tree()
all_tree_paths_tags = []
all_tags_index = 0


def init_smart_fuzzing_tree():
    init_start_time = time.time()
    global smart_fuzzing_tree

    # 0 Protocol_ID，通常为32
    print("已生成至0层")
    smart_fuzzing_tree.create_node(tag="32", identifier="root")

    # 1 ROSCTR，PDU type，PDU的类型，一般有以下值：
    print("已生成至1层")
    for nodes in smart_fuzzing_tree.leaves():
        smart_fuzzing_tree.create_node(tag="01", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="02", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="03", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="07", parent=nodes.identifier)
        # 其他
        smart_fuzzing_tree.create_node(tag="04", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="05", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="06", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="08", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="00", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="ff", parent=nodes.identifier)
    print("已生成至2层")
    # 2 Redundancy Identification (Reserved)，冗余数据，通常为0x0000
    for nodes in smart_fuzzing_tree.leaves():
        smart_fuzzing_tree.create_node(tag="0000", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="0001", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="ffff", parent=nodes.identifier)
    print("已生成至3层")
    # 3 Protocol Data Unit Reference，协议数据单元参考，通过请求事件增加
    for nodes in smart_fuzzing_tree.leaves():
        smart_fuzzing_tree.create_node(tag="0000", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="0001", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="ffff", parent=nodes.identifier)
    print("已生成至4层")
    # 4 Parameter length，参数长度
    for nodes in smart_fuzzing_tree.leaves():
        smart_fuzzing_tree.create_node(tag="%PL0", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="0000", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="ffff", parent=nodes.identifier)
    print("已生成至5层")
    # 5 Data length，数据长度
    for nodes in smart_fuzzing_tree.leaves():
        smart_fuzzing_tree.create_node(tag="%DL0", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="0000", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="ffff", parent=nodes.identifier)
    print("已生成至6层")
    # 6 Function Code，功能码
    for nodes in smart_fuzzing_tree.leaves():
        smart_fuzzing_tree.create_node(tag="28", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="29", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="04", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="05", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="06", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="07", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="1d", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="1e", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="1c", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="2a", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="2d", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="2e", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="0001120411430100", parent=nodes.identifier)

        smart_fuzzing_tree.create_node(tag="27", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="03", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="02", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="01", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="00", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="08", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="ff", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="fe", parent=nodes.identifier)

    print("已生成至7层")
    # 7 Item count or Reserv, 项目数或保留
    for nodes in smart_fuzzing_tree.leaves():
        smart_fuzzing_tree.create_node(tag="00", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(
            tag="01120a101d000200001d000001", parent=nodes.identifier
        )
        smart_fuzzing_tree.create_node(
            tag="01120a10020002000082000000", parent=nodes.identifier
        )
        smart_fuzzing_tree.create_node(
            tag="01120a10020001000184000008", parent=nodes.identifier
        )
        smart_fuzzing_tree.create_node(
            tag="ff120a10020002000082000000", parent=nodes.identifier
        )
        # 取自抓包中的部分除读写外的特殊功能数据
        smart_fuzzing_tree.create_node(
            tag="000000000009505f50524f4752414d", parent=nodes.identifier
        )
        smart_fuzzing_tree.create_node(
            tag="000000000000fd00000", parent=nodes.identifier
        )
        smart_fuzzing_tree.create_node(
            tag="000000000000fd000009505f50524f4752414d", parent=nodes.identifier
        )
        smart_fuzzing_tree.create_node(tag="ffffffff", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(
            tag="000000000000fd0002432009505f50524f4752414d", parent=nodes.identifier
        )
        smart_fuzzing_tree.create_node(
            tag="000000000000fd0000055f47415242", parent=nodes.identifier
        )
    print("已生成至8层")
    # 8 Data, 项目数或保留
    for nodes in smart_fuzzing_tree.leaves():
        smart_fuzzing_tree.create_node(tag="%end", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="000400100111", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(tag="ff0900023041", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(
            tag="ff0900083041303030303141", parent=nodes.identifier
        )
        smart_fuzzing_tree.create_node(tag="ff09000404240000", parent=nodes.identifier)
        smart_fuzzing_tree.create_node(
            tag="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            parent=nodes.identifier,
        )

    with open(get_time_str() + "init_smart_fuzzing_tree.pickle", "wb") as f:  # 打开文件
        pickle.dump(smart_fuzzing_tree, f)
        print("完成Fuzzing Tree初始化，并已序列化存储！")
        f.close()
        print("init_total_time is:" + str(time.time() - init_start_time) + " s.")
        print("total_nodes_number is:" + str(len(smart_fuzzing_tree)) + " .")
        exit(1)


def load_smart_fuzzing_tree():
    global smart_fuzzing_tree
    with open("2022-05-14-21_48_34init_smart_fuzzing_tree.pickle", "rb") as f:
        smart_fuzzing_tree = pickle.load(f)
        # print('已导入Fuzzing Tree，共' + str(len(smart_fuzzing_tree)) + '条')
        print("已导入Fuzzing Tree，共1327991条")
        f.close()


# 带覆盖率引导地生成S7_fuzz数据
def smart_generate_s7_fuzz_data(s7comm_data):
    """Create COTP"""
    COTP_Length = "02"
    COTP_PDU_Type = "f0"
    COTP_Last_data_unit = "80"
    COTP = COTP_Length + COTP_PDU_Type + COTP_Last_data_unit

    """ Create TPKT """
    TPKT_Version = "03"
    TPKT_Reserved = "00"
    TPKT_Length = str((int(len(COTP + s7comm_data) / 2) + 4)).zfill(4)
    TPKT = TPKT_Version + TPKT_Reserved + TPKT_Length

    """ the fuzz packet """
    fuzz_pkt = TPKT + COTP + s7comm_data
    return fuzz_pkt


def test_proccess(s7comm_data):
    local.counter = 0
    s = socket.socket()
    s.connect(("192.168.0.1", DPORT))
    ss = StreamSocket(
        s, Raw
    )  # StreamSocket是Scapy对原生Socket的包装增强。使用Kernel级别TCP Stack，故不再像前用户态版本一样需要手动配置防火墙规则拦截Kernel堆栈发出的RST数据包，且大大提升测试效率
    try:
        ss.sr(cotp_cr_packet, verbose=0)
        ss.sr(s7comm_setup_packet, verbose=0)
        while local.counter < 10:
            fuzz_packet = Packet(str2byte(smart_generate_s7_fuzz_data(s7comm_data)))
            ans = ss.sr1(fuzz(fuzz_packet), verbose=0)
            log_row = [
                byte2str(fuzz_packet.build()),
                byte2str(ans.build()),
                time.time(),
                MODE,
            ]
            FUZZ_LOG_WRITER.writerow(log_row)
            local.counter += 1
            print(
                "send:{}\nrecv{}".format(log_row[0], log_row[1]), end="\n************\n"
            )
    except:
        s.close()


def exstract_data_from_tags(tags: list):
    if "%DL0" in tags:
        if "%end" in tags:
            tags[tags.index("%DL0")] = "0000"
        else:
            tags[tags.index("%DL0")] = str(len(tags[-1]) / 2).zfill(4)
    if "%PL0" in tags:
        tags[tags.index("%PL0")] = str(int((len(tags[-1]) + len(tags[-2])) / 2)).zfill(
            4
        )
        print(tags[4])
    if "%end" in tags:
        tags[tags.index("%end")] = ""
    return "".join(tags)


if __name__ == "__main__":
    # init_smart_fuzzing_tree()
    load_smart_fuzzing_tree()
    tree_paths = smart_fuzzing_tree.paths_to_leaves()
    tree_paths_tags = [smart_fuzzing_tree.get_node(path).tag for path in tree_paths[0]]
    all_tree_paths_tags = [
        [smart_fuzzing_tree.get_node(path).tag for path in tree_path]
        for tree_path in tree_paths
    ]
    print(exstract_data_from_tags(all_tree_paths_tags[0]))
    test_proccess(exstract_data_from_tags(all_tree_paths_tags[all_tags_index]))
    exit(1)
    round = 0
    for i in range(1000):
        p1 = Process(
            target=test_proccess,
            args=(exstract_data_from_tags(all_tree_paths_tags[all_tags_index]),),
        )
        print(all_tree_paths_tags[all_tags_index])
        all_tags_index += 1
        # p2 =  Process(target=test_proccess)
        # p3 =  Process(target=test_proccess)
        p1.start()
        # p2.start()
        # p3.start()

        time.sleep(10)

        p1.terminate()
        # p2.terminate()
        # p3.terminate()

        p1.join()
        # p2.join()
        # p3.join()

        p1.close()
        # p2.close()
        # p3.close()
