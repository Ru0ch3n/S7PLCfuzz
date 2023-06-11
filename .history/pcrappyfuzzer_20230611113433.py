#!/usr/bin/python
# 将Scapy与radamsa结合，实现利用pcap包对西门子S7系列设备进行模糊测试
# Under developing
import scapy.all as scapy
from subprocess import Popen, PIPE
import ssl
import socket
import random
import time
import argparse
import os
import sys
import capture_main


VERBOSE = True
# 变异用的数据源
PCAP_LOCATION = "D:/Siemens/Simatic s7-200 SMART/2022-03-13-17_16_25/test_process2022-03-13-17_19_13.pcap"
# windows下需要借助cygwin才能使用radamsa
radamsa_bin = "E:/pen-tools/radamsa/bin/radamsa.exe"
clients_list = []
servers_list = []
packets_list = []

HOST = "192.168.0.1"
PORT = 102
FUZZ_FACTOR = 100


# 从radamsa_bin获取变异后的数据
def mutate(payload):
    try:
        radamsa = [radamsa_bin, "-n", "1", "-"]
        p = Popen(radamsa, stdin=PIPE, stdout=PIPE)
        mutated_data = p.communicate(payload.encode())[0]
        print(mutated_data)
    except:
        print("Could not execute 'radamsa'.")
        sys.exit(1)

    return mutated_data


# 打日志 到fuzz.log和error.log
def log_events(log_info, type_event):
    log_msg = "[" + time.ctime() + "]" + "\n" + log_info

    if type_event == "fuzzing":
        try:
            fd = open("fuzz.log", "a")
        except IOError as err:
            return "[!] Error opening log file: %s" % str(err)

    elif type_event == "error":
        try:
            fd = open("error.log", "a")
        except IOError as err:
            return "[!] Error opening error file: %s" % str(err)

    else:
        return "[!] '%s' is an unrecognized log event type." % type_event

    if fd:
        fd.write(log_msg)

    return


def main():
    global PCAP_LOCATION, HOST, PORT, FUZZ_FACTOR

    arg = argparse.ArgumentParser(
        description="A very simple mash-up of Scapy + radamsa to extract data from pcap and perform fuzzing ad infinitum."
    )
    arg.add_argument(
        "-H", action="store", dest="host", help="Destination IP - Default: 127.0.0.1"
    )
    arg.add_argument(
        "-p", action="store", dest="port", help="Destination Port - Port Default: 443"
    )
    arg.add_argument("-f", action="store", dest="file", help="Input File Location")
    arg.add_argument(
        "-z", action="store", dest="fuzz", help="Fuzz Factor - Default: 50.0"
    )
    arg.add_argument("-v", action="version", version="%(prog)s 1.0")

    result = arg.parse_args()

    if result.host:
        HOST = result.host
    if result.port:
        PORT = result.port
    if result.fuzz:
        FUZZ_FACTOR = result.fuzz
    if result.file:
        PCAP_LOCATION = result.file
    if not os.path.exists(PCAP_LOCATION):
        print("{} file not found. Please check".format(PCAP_LOCATION))
        exit(1)
    pktcounter = 0
    packets = scapy.rdpcap(PCAP_LOCATION)
    random.seed(time.time())

    print("This pcap contains a total of %d packets. Parsing..." % len(packets))

    """
    Extract the payload of all client->server packets, put them in an
    ordered list for subsequent fuzzing.
    """
    for pkt in packets:
        """
        So we can tell since the very begining who is the client and the
        server. We assume the client initiates the connection with a packet
         with SYN as the only flag activated.
        """
        if "TCP" not in pkt:
            continue
        if pktcounter == 0:
            if pkt["TCP"].sprintf("%TCP.flags%") == "S":
                clients_list.append(pkt["IP"].src)
                servers_list.append(pkt["IP"].dst)

        if VERBOSE:
            print("Parsing packet #%d" % pktcounter)
            print(pkt.summary())
        pktcounter += 1
        try:
            if pkt["Raw"]:
                """
                We make sure we only fuzz data traveling from the client to
                the server, in this case is the only thing we're interested
                as we're fuzzing the back-end application
                """
                if pkt["IP"].src in clients_list:
                    print(
                        "Packet #%d has some client->server raw data. Go fuzz!"
                        % pktcounter
                    )
                    packet_payload = pkt["Raw"]
                    packets_list.append((pktcounter, str(packet_payload)))
        except IndexError:
            continue

    ##################测试变异效果
    for packet in packets_list:
        payload = packet[1]
        if random.random() < FUZZ_FACTOR / 100:
            mulated = mutate(payload)
            print(payload, "\n--变异-->\n", mulated)
    exit(233)
    ##############################################

    # Infinite loop of mutating packets and them down the wire
    fuzz_iterations = 0
    print("HOST:", HOST, " clients_list:", clients_list, " server_list:", servers_list)

    while True:
        iterations_str = "[+] Fuzzing iteration number #%d" % fuzz_iterations
        print(iterations_str)

        try:
            fuzz_iterations += 1
            sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockfd.settimeout(5)
            ssl_sockfd = ssl.wrap_socket(sockfd)
            ssl_sockfd.connect((HOST, PORT))

            for packet in packets_list:
                payload = packet[1]
                if random.random() < FUZZ_FACTOR / 100:
                    payload = mutate(payload)
                    print(payload)

                iterations_str += "\n" + "--- Payload ---\n" + payload + "\n"
                print(payload)

                ssl_sockfd.send(payload)
                received_buffer = ssl_sockfd.recv(2048)

                iterations_str += "\n" + "--- Received ---\n" + received_buffer + "\n"
                print(received_buffer)

                log_events(iterations_str + "\n", "fuzzing")

                print("")

        except Exception as err:
            error_str = "[!] Error during iteration #%d: %s" % (
                fuzz_iterations,
                str(err),
            )
            print(error_str)
            log_str = error_str + "\n" + iterations_str
            log_events(log_str, "error")


if __name__ == "__main__":
    main()
