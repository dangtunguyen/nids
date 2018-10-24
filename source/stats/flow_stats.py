#!/usr/bin/env python

from scapy.all import *
import numpy as np
import socket
import struct
import dpkt
import utils
from time import time

class FlowStats:
    def __init__(self, ip):
        self.src_ip_str = ip.src
        self.src_ip_int = utils.inet_to_int(ip.src)
        self.dst_ip_str = ip.dst
        self.dst_ip_int = utils.inet_to_int(ip.dst)
        self.proto = ip.proto
        self.src_port = 0
        self.dst_port = 0
        self.tcpflag = 0
        self.icmp_error = 0
        self.tcp_syn_ack = 0
        self.tcp_ack_to_syn_ack = 0
        self.transport_error = 0 ## Error code in transport layer (TCP/UDP)
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.tx_packets = 0
        self.rx_packets = 0
        self.brand_new = True
        self.created_time = 0
        self.last_update = 0
        if utils.off_line == 1:
            self.created_time = utils.cur_time
            self.last_update = utils.cur_time
        else:
            self.created_time = time()
            self.last_update = time()
        
        self.update_tcp_fields(ip)
        self.update_udp_fields(ip)
        self.update_icmp_fields(ip)
        
    def update_stats(self, ip):
        self.update_icmp_fields(ip)
        self.update_tcp_flag(ip)
        self.update_traffic_stats(ip)
        if utils.off_line == 1:
            self.last_update = utils.cur_time
        else:
            self.last_update = time()
        
    def update_traffic_stats(self, ip):
        if ip.src == self.src_ip_str:
            self.tx_bytes += ip.len
            self.tx_packets += 1
        else:
            self.rx_bytes += ip.len
            self.rx_packets += 1
    
    def reset_traffic_stats(self):
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.tx_packets = 0
        self.rx_packets = 0
    
    def update_tcp_fields(self, ip):
        ## Extract TCP fields            
        if TCP in ip:
            tcp = ip[TCP]
            self.src_port = tcp.sport
            self.dst_port = tcp.dport
            self.tcpflag |= tcp.flags
            
    def update_udp_fields(self, ip):
        ## Extract UDP fields            
        if UDP in ip:
            udp = ip[UDP]
            self.src_port = udp.sport
            self.dst_port = udp.dport
            self.update_traffic_stats(ip)
            
    def update_icmp_fields(self, ip):
        ## Extract ICMP fields
        if ICMP in ip:
            self.update_traffic_stats(ip)
            icmp = ip[ICMP]
            if icmp.type in utils.ICMP_ERR_TYPES:
                self.icmp_error = 1
                
    def update_tcp_flag(self, ip):
        if TCP in ip:
            tcp = ip[TCP]
            self.tcpflag |= tcp.flags
            
            ## Check if SYN_ACK is received after requesting a new connection
            ## (SYN packet was sent)
            if (self.tcpflag & dpkt.tcp.TH_SYN) != 0:
                if tcp.flags == utils.TCP_SYN_ACK:
                    self.tcp_syn_ack = 1
            
            ## Check if an ACK message is sent after receiving SYN_ACK
            if self.tcp_syn_ack == 1:
                if tcp.flags == dpkt.tcp.TH_ACK:
                    self.tcp_ack_to_syn_ack = 1
                    
    def is_stale(self):
        dif = 0
        if utils.off_line == 1:
            dif = utils.cur_time - self.last_update
        else:
            dif = time() - self.last_update
        if self.proto == 6:
            return (dif > utils.TCP_TTL)
        else:
            return (dif > utils.UDP_TTL)           
    
    def is_conn_closed(self):
        if self.proto == 6:
            return ((self.tcpflag & dpkt.tcp.TH_FIN) != 0)
        return False
    
    def validate_transport_layer(self):
        '''
        transport_error is set to 1 when either of the following conditions is met
        - TCP RST flag is on
        - TCP [SYN, ACK] is not received
        - TCP ACK is not sent after TCP [SYN, ACK] is received
        UDP errors are identified via ICMP errors (e.g., destination unreachable)
        '''
        if self.proto == 6:
            if ((self.tcpflag & dpkt.tcp.TH_RST) != 0):
                self.transport_error = 1
            t = 0
            if utils.off_line == 1:
                t = utils.cur_time
            else:
                t = time()
            if (t-self.created_time) > utils.TCP_SETUP_TIME:
                if (self.tcp_syn_ack == 0) or (self.tcp_syn_ack == 1 and self.tcp_ack_to_syn_ack == 0):
                    self.transport_error = 1
    
    def is_erroneous(self):
        self.validate_transport_layer()
        if (self.icmp_error != 0) or (self.transport_error != 0):
            return True
        return False           
        
    def get_stats(self):
        arr = np.zeros(utils.LSTM_FLOW_FEATURES) ## 12 features
        arr[0] = utils.get_norm_val(self.src_ip_int, utils.MAX_IP)
        arr[1] = utils.get_norm_val(self.dst_ip_int, utils.MAX_IP)
        arr[2] = utils.get_norm_val(self.src_port, utils.MAX_PORT)
        arr[3] = utils.get_norm_val(self.dst_port, utils.MAX_PORT)
        arr[4] = utils.get_norm_val(self.proto, utils.MAX_PROTO)
        arr[5] = utils.get_norm_val(int(self.tcpflag), utils.MAX_TCP_FLAG)
        arr[6] = self.icmp_error
        arr[7] = self.transport_error
        arr[8] = utils.get_norm_val(self.tx_bytes, utils.MAX_TX_BYTES)
        arr[9] = utils.get_norm_val(self.rx_bytes, utils.MAX_RX_BYTES)
        arr[10] = utils.get_norm_val(self.tx_packets, utils.MAX_TX_PACKETS)
        arr[11] = utils.get_norm_val(self.rx_packets, utils.MAX_RX_PACKETS)
        
        self.reset_traffic_stats()
        t = 0
        if utils.off_line == 1:
            t = utils.cur_time
        else:
            t = time()
        if (t-self.created_time) > utils.TCP_SETUP_TIME:
            self.brand_new = False
        
        return arr
        
    def print_stats(self):
        print("src_ip:{},dst_ip:{},src_port:{},dst_port:{},proto:{},tcpflags:{},icmp_error:{},transport_error:{},tx_bytes:{},rx_bytes:{},tx_packets:{},rx_packets:{},tcp_syn_ack:{},tcp_ack_to_syn_ack:{}".format(self.src_ip_str, self.dst_ip_str, self.src_port, self.dst_port, self.proto, self.tcpflag, self.icmp_error, self.transport_error, self.tx_bytes, self.rx_bytes, self.tx_packets, self.rx_packets, self.tcp_syn_ack, self.tcp_ack_to_syn_ack))
        
    def get_flow_tuple(self):
        result = ''
        result += 'src_ip:' + self.src_ip_str + ', dst_ip:' + self.dst_ip_str + ', src_port:' + str(self.src_port) + ', dst_port:' + str(self.dst_port)
        return result
        
    def get_label(self):
        #print(utils.cur_time)
        if self.dst_ip_str == '169.235.25.9' and self.dst_port == 121 and self.is_erroneous() == True:
            #self.print_stats()
            return 1
        return 0
