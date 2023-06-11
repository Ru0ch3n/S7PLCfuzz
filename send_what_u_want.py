import csv
import multiprocessing
import threading
from datetime import time
from socket import socket
from time import sleep

from scapy.packet import Raw, Packet
from scapy.supersocket import StreamSocket
from treelib import Tree

from fuzz_plusplusplus_stable import exstract_data_from_tags
from fuzz_plusplusplusbugfix import load_smart_fuzzing_tree, exstract_data_from_tags_list
from utils.utils import str2byte, simatic_200_smart_hello, set_comm, byte2str, minDistanceRatio

FUZZ_LOG_CSV = open('fuzz_log.csv', 'a+')
FUZZ_LOG_WRITER = csv.writer(FUZZ_LOG_CSV)

MODE = 'fuzz_main_bug_fix'

smart_fuzzing_tree = Tree()
all_tree_paths_tags = []
all_tags_index = 0

def get_s7_smart_fuzz_data(s7comm_data):
    COTP_Length = '02'
    COTP_PDU_Type = 'f0'
    COTP_Last_data_unit = '80'
    COTP = COTP_Length + COTP_PDU_Type + COTP_Last_data_unit

    Data = s7comm_data

    TPKT_Version = '03'
    TPKT_Reserved = '00'
    TPKT_Length = hex((int(len(COTP + Data)/2) + 4))[2:].zfill(4)
    TPKT = TPKT_Version + TPKT_Reserved + TPKT_Length

    fuzz_pkt = TPKT + COTP + s7comm_data

    print(fuzz_pkt)
    return fuzz_pkt

def traverse_fuzz_data(send_recv_dict:dict, send_recv_tag, presaved_five):
    presaved_five = []
    while True:
        if minDistanceRatio(presaved_five[4][1],presaved_five[3][1]) > 0.95 and \
                minDistanceRatio(presaved_five[4][1],presaved_five[2][1]) > 0.95 and\
                minDistanceRatio(presaved_five[4][1],presaved_five[1][1]) > 0.95 and\
                minDistanceRatio(presaved_five[4][1],presaved_five[0][1]) > 0.95:
            send_recv_tag += 11 * 6 #跳到下一功能组
        else:
            send_recv_tag += 1
        data = exstract_data_from_tags(all_tree_paths_tags[all_tags_index])
        send_recv_dict[data] =''

        '''dictB = {}
        for key, value in send_recv_dict.items():
            dictB.setdefault(value, set()).add(value)
            res = filter(lambda x: len(x) > 1, dictB.values())
            same_or_similar_dict = dict(filter(lambda x: minDistanceRatio(x[1],x[1]), dictB.items()))
'''

def send_fuzz_data(send_recv_dict:dict):
    counter = 0
    s = socket()
    s.connect(("192.168.0.1", 102))
    ss = StreamSocket(s, Raw)
    try:
        ss.sr(Packet(str2byte(simatic_200_smart_hello)), verbose=0)
        ss.sr(Packet(str2byte(set_comm)), verbose=0)
        # 筛选出值为空的，即未收到回复的消息
        unsend_dict = dict(filter(lambda x: x[1] == '', send_recv_dict.items()))
        while counter < 6:
            if not bool(unsend_dict):
                break
            unsend = unsend_dict.popitem()[0]
            fuzz_packet = Packet(str2byte(get_s7_smart_fuzz_data(unsend)))
            ans= ss.sr1(fuzz_packet, verbose=0)
            #加入缓存队列
            presaved_five.insert(0, (unsend, ans))
            presaved_five.pop()
            send_recv_dict[unsend] =  byte2str(ans.build())
            log_row = [byte2str(fuzz_packet.build()), byte2str(ans.build()), time(), MODE]
            print(log_row)
            FUZZ_LOG_WRITER.writerow(log_row)

            counter += 1
            print('send:{}\nrecv{}'.format(log_row[0], log_row[1]), end='\n************\n')
    except:
        s.close()



if __name__ == '__main__':
    load_smart_fuzzing_tree()
    tree_paths = smart_fuzzing_tree.paths_to_leaves()

    tree_paths_tags = [smart_fuzzing_tree.get_node(path).tag for path in tree_paths[0]]
    all_tree_paths_tags = [[smart_fuzzing_tree.get_node(path).tag for path in tree_path] for tree_path in tree_paths]


    # 多进程间共享变量靠该Manager生成的对象
    mgr = multiprocessing.Manager()
    # 把像发送的赋给该字典即可进行发送
    send_recv_dict = mgr.dict({'222222222111111111111111111111':''})
    send_recv_tag = mgr.Value(value=1)
    presaved_five = mgr.list()

    p2 = threading.Thread(target=traverse_fuzz_data, args=(send_recv_dict, send_recv_tag, presaved_five,))
    p2.start()
    sleep(20)#等加载到send_recv_dict
    p1 = threading.Thread(target=send_fuzz_data,args=(send_recv_dict,presaved_five ))
    p1.start()

    '''
    send_fuzz_data(send_recv_dict)
    send_fuzz_data(send_recv_dict)
    '''
    print(send_recv_dict)
