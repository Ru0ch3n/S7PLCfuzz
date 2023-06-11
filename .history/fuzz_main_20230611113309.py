# -*- coding: utf-8 -*-
import binascii
from scapy.all import *
from scapy.layers.inet import TCP, IP

hello =                   "03000016" + "11e00000001200c1020100c2020102c0010a"
simatic_200_smart_hello = "03000016" + "11e00000000100c0010ac1020100c2020200"
set_comm =                "03000019" + "02f080"  + "32010000000000080000f0000001000101e0"
message_str = "0300002102f080320700000100000800080001120411440100ff09000400110000"
ROSCTR_dict = {0: '01', 1: '07'}
userdata_dict = {0: '01', 1: '02', 2: '03', 3: '07'}
Group_funciton_dict = {
    1: {0: '01', 1: '02', 2: '0c', 3: '0e', 4: '0f', 5: '10', 6: '13'},
    2: {0: '01', 1: '04'},
    3: {0: '01', 1: '02', 2: '03'},
    4: {0: '01', 1: '02', 2: '03'},
    5: {0: '01'},
    6: {0: ''},
    7: {0: '01', 1: '02', 2: '03', 3: '04'}
}
Return_code_dict = {0: '00', 1: '01', 2: '03', 3: '05', 4: '06', 5: '07', 6: '0a', 7: 'ff'}
Transport_size_dict = {0: '00', 1: '03', 2: '04', 3: '05', 4: '06', 5: '07', 6: '09'}
testdata_str = "0300002102f080320700000100000800080001120411440100ff09000400110000"
''' S/SA/A/PA/R'''
flags = {0: 2, 1: 18, 2: 16, 3: 24, 4: 4}

def iface_getter(packet):
    try:
        iff = next(packet.__iter__()).route()[0]
    except AttributeError:
        iff = None
    return iff or conf.iface



def generate_random_string(n):
    hex_alphabet = '0123456789abcdef'
    random_string = ''
    for i in range(n):
        random_string += hex_alphabet[random.randint(0,15)]
    return random_string


def str2byte(data):
    result = bytes.fromhex(data)
    return result


def s7_fuzz_packet():
    ''' Create TPKT '''

    TPKT_Version = '03'
    TPKT_Reserved = '00'
    # TPKT_Length = randomString(1).zfill(2) + randomString(1).zfill(2)
    TPKT_Length = ((hex(random.randint(58, 60)))[2:]).zfill(4)
    TPKT = TPKT_Version + TPKT_Reserved + TPKT_Length

    ''' Create COTP '''

    COTP_Length = '02'
    # COTP_PDU_Type = ((hex(random.randint(0, 16)))[2:]) + '0'
    COTP_PDU_Type = 'f0'
    COTP_Last_data_unit = '80'
    COTP = COTP_Length + COTP_PDU_Type + COTP_Last_data_unit

    ''' S7-Head'''

    Protocol_ID = '32'
    ROSCTR = ROSCTR_dict[random.randint(0, 1)]
    Redundancy_Identification = '0000'
    Protocol_Data_Unit_Reference = generate_random_string(2).zfill(4)
    Parameter_Length = '0008'
    Head_Data_Length = (
        hex(
            int(((int(TPKT_Length, 16))*2 - 14 - 36)/2)
        )[2:]).zfill(4)
    Header = Protocol_ID + ROSCTR + Redundancy_Identification + Protocol_Data_Unit_Reference\
             + Parameter_Length + Head_Data_Length

    ''' S7-Parameter '''
    Parameter_head = '000112'
    Parameter_length = '04'
    Parameter_Request = generate_random_string(1).zfill(2)
    # Parameter_Type = str(random.randint(0, 16))
    Parameter_Type = (generate_random_string(1))[0]
    Parameter_FunctionGroup = random.randint(1, 7)
    Parameter_subfunciton = choice(Group_funciton_dict[Parameter_FunctionGroup])
    Parameter_FunctionGroup = str(Parameter_FunctionGroup)
    Parameter_Sequence_number = generate_random_string(1).zfill(2)
    Parameter = Parameter_head + Parameter_length + Parameter_Request + Parameter_Type + Parameter_FunctionGroup\
                + Parameter_subfunciton + Parameter_Sequence_number

    ''' S7-Data '''
    Data_ReturnCode = Return_code_dict[random.randint(0, 7)]
    Data_Transport_size = Transport_size_dict[random.randint(0, 6)]
    Data_Length = (
                      (int(Head_Data_Length, 16) * 2) - 8
                  )/2
    Data_Data = ''
    Data_Data = generate_random_string(int(Data_Length)).zfill(int(Data_Length) * 2)
    Data_Length = (hex(int(Data_Length)))[2:].zfill(4)
    Data = Data_ReturnCode + Data_Transport_size + Data_Length + Data_Data

    ''' the fuzz packet '''
    fuzz_pkt = TPKT + COTP + Header + Parameter + Data
    return fuzz_pkt

def fuzz_sniff():
    sniffer = sniff(filter="tcp and host 172.18.15.108", count=3)
    for i in range(len(sniffer)):
        tcp_flag = sniffer[i][2].flags
        if tcp_flag == 24:
            tcp_load = sniffer[1][2].load
            if tcp_load[:1] == '\x03\x00':
                error_code = tcp_load[-2:]
                print(error_code)

def tcp_connect():
    #SYN
    SYN = TCP(sport=sport, dport=dport, flags='S', seq=0)
    SYNACK = sr1(ip/SYN)

    #ACK
    ACK = TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    send(ip  /  ACK)

    return SYNACK

def COTP_CC_AND_S7COMM_REQ(SYNACK):
    #发送 COTP CR，收到 COTP CC
    COTP_CR = ip / TCP(sport=sport, dport=dport, flags='PA', seq=SYNACK.ack, ack=SYNACK.seq + 1) /\
              str2byte(simatic_200_smart_hello)
    #COTP_CC = sr1(COTP_CR , multi=True, timeout=2)
    COTP_CC = sr(COTP_CR , multi=True, timeout=2, iface=iface_getter(COTP_CR))

    #发送 S7COMM_SETUP_REQUEST ，收到S7COMM_SETUP_CONFORM
    S7COMM_SETUP_REQUEST = ip /\
                           TCP(sport=sport, dport=dport, flags='PA', seq=COTP_CC[0][1][1].ack,
                               ack=COTP_CC[0][1][1].seq + len(COTP_CC[0][1][1].load)) /\
                           str2byte(set_comm)
    S7COMM_SETUP_CONFORM = sr(S7COMM_SETUP_REQUEST , multi=True, timeout=3, iface=iface_getter(S7COMM_SETUP_REQUEST))
    #发送 TCP ack
    comm_ack = TCP(sport=sport, dport=dport, flags='A',
                   seq=S7COMM_SETUP_CONFORM[0][1][1].ack,
                   ack=S7COMM_SETUP_CONFORM[0][1][1].seq + len(S7COMM_SETUP_CONFORM[0][1][1].load))
    send(ip/comm_ack)

    return S7COMM_SETUP_CONFORM


def fuzz(comm_ack):
    fuzz_pkt = str2byte(s7_fuzz_packet())
    # fuzz_ack = sr(ip/fuzzpkt/fuzz_pkt, multi=True, timeout=5)

    fuzz_package = ip / TCP(sport=sport, dport=dport, flags='PA', seq=comm_ack[0][1][1].ack , ack=comm_ack[0][1][1].seq + len(comm_ack[0][1][1].load)) / fuzz_pkt

    fuzz_ack = sr(fuzz_package, iface=iface_getter(fuzz_package))
    sniffer = sniff(filter="tcp and host 172.18.15.108", count=2, timeout=2)
    return sniffer, fuzz_pkt, fuzz_ack


def fuzz_analysis(data):
    if len(data[0]) == 0:
        fuzzlog.write("%s\n" % binascii.hexlify(data[1]))
    else:
        errorlog.write("%s \n" % binascii.hexlify(data[0][1][2].load[-2:]))
    rst = TCP(sport=sport, dport=dport, flags='R')
    send(ip/rst)



# 工作模式
if len(sys.argv) >= 3:
    src = sys.argv[1]
    dst = sys.argv[2]
    dport = int(sys.argv[3])
else:
    src = '192.168.0.241'
    dst = '192.168.0.1'
    dport = 102


if __name__=='__main__':
    fuzzlog = open('fuzzlog.log', 'w+')
    errorlog = open('error_code.log', 'w+')

    while True:
        sport = random.randint(60000,65535)
        ip = IP(src=src, dst=dst)
        syn_ack = tcp_connect()
        comm_ack = COTP_CC_AND_S7COMM_REQ(syn_ack)
        fuzz_result = fuzz(comm_ack)
        fuzz_analysis(fuzz_result)
