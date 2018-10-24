#!/usr/bin/env python

from scapy.all import *
from time import time
import utils

class ContextStats:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.tx_bytes = 0
        self.tx_packets = 0
        self.rx_bytes = 0
        self.rx_packets = 0
        self.src_connections = 0 # number of connections originating from this ip_addr
        self.dst_connections = 0 # number of connections towards this ip_addr
        self.src_errors = 0 # number of errors caused by this source ip_addr
        self.dst_errors = 0 # number of errors happening to this destination ip_addr
        
        ## Accumulated stats
        self.accu_src_connections = 0
        self.accu_dst_connections = 0
        self.accu_src_errors = 0
        self.accu_dst_errors = 0
        if utils.off_line == 1:
            self.last_err_conn_reset = utils.cur_time
        else:
            self.last_err_conn_reset = time()
        
    def update_traffic_stats(self, ip):
        if ip.src == self.ip_addr:
            self.tx_bytes += (float)(ip.len)/1000
            self.tx_packets += 1
        if ip.dst == self.ip_addr:
            self.rx_bytes += (float)(ip.len)/1000
            self.rx_packets += 1

    def update_connections_stats(self, ip):
        if ip.src == self.ip_addr:
            self.src_connections += 1
            self.accu_src_connections += 1
        if ip.dst == self.ip_addr:
            self.dst_connections += 1
            self.accu_dst_connections += 1
            
    def reset_stats(self):
        self.tx_bytes = 0
        self.tx_packets = 0
        self.rx_bytes = 0
        self.rx_packets = 0
        
        ## Check if error and connection counts should be reset to current stats values
        t = 0
        if utils.off_line == 1:
            t = utils.cur_time
        else:
            t = time()
        if (t-self.last_err_conn_reset) > utils.ERR_CONN_TTL:
            print("Reset accumulated error and connection counts to stats values")
            self.last_err_conn_reset = t
            self.accu_src_connections = self.src_connections
            self.accu_dst_connections = self.dst_connections
            self.accu_src_errors = self.src_errors
            self.accu_dst_errors = self.dst_errors
        
    def print_stats(self):
        print("ip:{},tx_bytes:{},tx_packets:{},rx_bytes:{},rx_packets:{},src_conn:{},dst_conn:{},src_errors:{},dst_errors:{},accu_src_conn:{},accu_dst_conn:{},accu_src_errors:{},accu_dst_errors:{}".format(self.ip_addr, self.tx_bytes, self.tx_packets, self.rx_bytes, self.rx_packets, self.src_connections, self.dst_connections, self.src_errors, self.dst_errors, self.accu_src_connections, self.accu_dst_connections, self.accu_src_errors, self.accu_dst_errors))
        
