import os
import socket
from ctypes_test import Ip
from ctypes_test import Icmp

if os.name == 'nt':
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)  # WIN 开启IPPROTO的ip模式
    sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 端口复用
else:
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)  # linux 开启IPPROTO的icmp模式
sniffer.bind(('192.168.43.87', 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # 设置抓获数据包，//,包含ip头43
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # 开启混杂模式
try:
    while True:
        b_sniffer, addr = sniffer.recvfrom(10240)
        b_sniffer1 = Ip(b_sniffer[:20])
        print("Protocol: %s %s -> %s " % (b_sniffer1.protocol, b_sniffer1.src_address, b_sniffer1.dst_address))
        if b_sniffer1.protocol == "ICMP":
            offset = b_sniffer1.ihl * 4
            buf = b_sniffer[offset:offset + sizeof(ICMP)]

            icmp_header = Icmp(buf)
            print("ICMP -> Type:%d Code:%d " % (icmp_header.type, icmp_header.code))

except:
    pass
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
