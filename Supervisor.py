#! /usr/bin/env python
import csv
import time

from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP

from fuzz_main import iface_getter
from fuzz_plus import simatic_200_smart_hello
from utils.utils import str2byte
from pymodbus.client.sync import ModbusTcpClient

iface_example = IP(src='192.168.0.241', dst='192.168.0.1') / TCP(sport=65500, dport=102, flags='PA') /\
              str2byte(simatic_200_smart_hello)
fact_iface=iface_getter(iface_example)
max_tolerate = 3 #设置3秒等待时间

def ICMP_check():
    ans = sr1(IP(dst="192.168.0.1")/ICMP(), iface=fact_iface)
    FUZZ_LOG_CSV = open('fuzz_log.csv', 'a+')
    FUZZ_LOG_WRITER = csv.writer(FUZZ_LOG_CSV)
    FUZZ_LOG_WRITER.writerow(['ICMP Check', str(ans.src) ,time.time()])

def Modbus_check():
    global max_tolerate
    FUZZ_LOG_CSV = open('fuzz_log.csv', 'a+')
    FUZZ_LOG_WRITER = csv.writer(FUZZ_LOG_CSV)
    try:
        print('Modbus运行检查')
        client = ModbusTcpClient('192.168.0.1', port = 502, timeout = 1)
        request = client.read_input_registers(1,5)
        time.sleep(max_tolerate)
        ans = request.registers
        FUZZ_LOG_WRITER.writerow(['MODBUS Check', 'MODBUS OK' ,time.time()])
        print('检查完成，无问题:')
    except:
        FUZZ_LOG_WRITER.writerow(['MODBUS Check', 'MODBUS WRONG', time.time()])
        print('检查完成，有问题:'+str(max_tolerate)+'秒内未能及时返回，业务堵塞！')
        print(traceback.format_exc())
    try:
        FUZZ_LOG_CSV.close()
    except:
        pass
while True:
    Modbus_check()
    time.sleep(6)