#!/usr/bin/env python
# coding: utf-8
# author: frk

import sys

import struct
import socket
from socket import inet_ntoa
import os

reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF8')
Int2Ip = lambda x: '.'.join([str(x / (256 ** i) % 256) for i in range(3, -1, -1)])


def Ip2Int(ip_string):
    return struct.unpack("!I", socket.inet_aton(ip_string))[0]


_unpack_V = lambda b: struct.unpack("<L", b)
_unpack_N = lambda b: struct.unpack(">L", b)
_unpack_C = lambda b: struct.unpack("B", b)


class IP:
    offset = 0
    index = 0
    binary = ""

    @staticmethod
    def load(file):
        try:
            path = os.path.abspath(file)
            with open(path, "rb") as f:
                IP.binary = f.read()
                IP.offset, = _unpack_N(IP.binary[:4])
                IP.index = IP.binary[4:IP.offset]
        except Exception as ex:
            print "cannot open file %s" % file
            print ex.message
            exit(0)

    @staticmethod
    def totxt():
        index = IP.index
        offset = IP.offset
        binary = IP.binary
        start, = _unpack_V(index[0:4])
        max_comp_len = offset - 1028
        start = start * 8 + 1024
        record = {}
        while start < (max_comp_len-8):
            startip = inet_ntoa(index[start:start + 4])
            stopip = inet_ntoa(index[start + 8:start + 12])
            startip = Int2Ip(Ip2Int(startip) + 1)
            start += 8
            index_offset, = _unpack_V(index[start + 4:start + 7] + chr(0).encode('utf-8'))
            index_length, = _unpack_C(index[start + 7])
            res_offset = offset + index_offset - 1024
            region_isp = binary[res_offset:res_offset + index_length].decode('utf-8')
            riList = region_isp.split('\t')
            record['region'] = riList[0] + ',' + riList[1] + ',' + riList[2] + ',' + '@' + riList[4]
            print startip, ",", stopip, ",", Ip2Int(startip), ",", Ip2Int(stopip), ",", record['region']

IP.load(os.path.abspath(sys.argv[1]))
IP.totxt()