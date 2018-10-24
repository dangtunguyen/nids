#!/usr/bin/env python

from scapy.all import *
import numpy as np
import socket
import struct
import dpkt

######################################################################
# Total number of packet dimensions
NUM_HEADER_FIELDS = 22

# Index values for IP header fields
SIP_INDEX = 0 # Source IP
DIP_INDEX = 1 # Destination IP
DF_INDEX= 2 # Do not fragment flag
MF_INDEX = 3 # More fragments flag
TTL_INDEX = 4 # Time to live
PROTO_INDEX = 5 # Protocol: 1 = ICMP; 2 = IGMP; 6 = TCP; 17 = UDP

# Index values for common TCP/UDP header fields
SPORT_INDEX = 6 # Source port
DPORT_INDEX = 7 # Destination port

# Index values for common TCP/UDP/ICMP header fields
CHECKSUM_INDEX = 8

# Index values for common TCP header fields
SEQ_INDEX = 9
ACK_INDEX = 10
WIN_INDEX = 11
FIN_INDEX = 12
SYN_INDEX = 13
RST_INDEX = 14
PUSH_INDEX = 15
TCP_ACK_INDEX = 16
URG_INDEX = 17
ECE_INDEX = 18
CWR_INDEX = 19

# Index values for common ICMP header fields
TYPE_INDEX = 20
CODE_INDEX = 21

# Max values for normalization
MAX_SPORT = 65531
MAX_DPORT = 65416
MAX_SEQ = 4293617831
MAX_ACK = 4293617831
MAX_WIN = 65535
MAX_SUM = 65528
MAX_S_IP = 3757027264
MAX_D_IP = 3744647062
MAX_TTL = 255
MAX_PROTO = 255
MAX_TYPE = 255
MAX_CODE = 255

## IPv4 flags
DF_FLAG = 2 ## Do not fragment
MF_FLAG = 1 ## More fragments
######################################################################
def inet_to_str(ip_string):
	try:
		ip_struct = socket.inet_aton(ip_string)
		return struct.unpack("!L", ip_struct)[0]
	except ValueError:
		print("[inet_to_str] Something went wrong!!!")

def normalize(value, data_max):
	if value >= data_max:
		return 1.0
	else:
		return (value - 0.000) / (data_max - 0.0000)

def extract_normalized_fields(ip):
	## Initialize the normalized array of header fields
	norm_arr = np.zeros(NUM_HEADER_FIELDS)
	
	## Extract IP fields
	norm_arr[SIP_INDEX] = normalize(inet_to_str(ip.src), MAX_S_IP)
	norm_arr[DIP_INDEX] = normalize(inet_to_str(ip.dst), MAX_D_IP)
	norm_arr[DF_INDEX] = (ip.flags & DF_FLAG) != 0
	norm_arr[MF_INDEX] = (ip.flags & MF_FLAG) != 0
	norm_arr[TTL_INDEX] = normalize(ip.ttl, MAX_TTL)
	norm_arr[PROTO_INDEX] = normalize(ip.proto, MAX_PROTO)
    
    ## Extract TCP fields            
	if TCP in ip:
		tcp = ip[TCP]
		norm_arr[SPORT_INDEX] = normalize(tcp.sport, MAX_SPORT)
		norm_arr[DPORT_INDEX] = normalize(tcp.dport, MAX_DPORT)
		norm_arr[CHECKSUM_INDEX] = normalize(tcp.chksum, MAX_SUM)
		norm_arr[SEQ_INDEX] = normalize(tcp.seq, MAX_SEQ)
		norm_arr[ACK_INDEX] = normalize(tcp.ack, MAX_ACK)
		norm_arr[WIN_INDEX] = normalize(tcp.window, MAX_WIN)
		## TCP flags
		norm_arr[FIN_INDEX] = (tcp.flags & dpkt.tcp.TH_FIN) != 0
		norm_arr[SYN_INDEX] = (tcp.flags & dpkt.tcp.TH_SYN) != 0
		norm_arr[RST_INDEX] = (tcp.flags & dpkt.tcp.TH_RST) != 0
		norm_arr[PUSH_INDEX] = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
		norm_arr[TCP_ACK_INDEX] = (tcp.flags & dpkt.tcp.TH_ACK) != 0
		norm_arr[URG_INDEX] = (tcp.flags & dpkt.tcp.TH_URG) != 0
		norm_arr[ECE_INDEX] = (tcp.flags & dpkt.tcp.TH_ECE) != 0
		norm_arr[CWR_INDEX] = (tcp.flags & dpkt.tcp.TH_CWR) != 0
	
	## Extract UDP fields            
	if UDP in ip:
		udp = ip[UDP]
		norm_arr[SPORT_INDEX] = normalize(udp.sport, MAX_SPORT)
		norm_arr[DPORT_INDEX] = normalize(udp.dport, MAX_DPORT)
		norm_arr[CHECKSUM_INDEX] = normalize(udp.chksum, MAX_SUM)
	
	## Extract ICMP fields            
	if ICMP in ip:
		icmp = ip[ICMP]
		norm_arr[CHECKSUM_INDEX] = normalize(icmp.chksum, MAX_SUM)
		norm_arr[TYPE_INDEX] = normalize(icmp.type, MAX_TYPE)
		norm_arr[CODE_INDEX] = normalize(icmp.code, MAX_CODE)
		
	return norm_arr
			
if __name__ == '__main__':
	ip1 = inet_to_str('10.0.0.1')
	ip2 = inet_to_str('10.0.0.1')
	
	if ip1 == ip2:
		print("ip:{}".format(ip1))
	else:
		print("ip1:{}, ip2:{}".format(ip2))
