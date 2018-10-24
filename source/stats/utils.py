#!/usr/bin/env python

from scapy.all import *
import numpy as np
import socket
import struct
import dpkt

##############################################
## Definitions of constants
TCP_SYN_ACK = 0
TCP_SYN_ACK |= dpkt.tcp.TH_SYN
TCP_SYN_ACK |= dpkt.tcp.TH_ACK
TCP_TTL = 300 ## seconds
UDP_TTL = 50 ## seconds
TCP_SETUP_TIME = 3 ## seconds
ERR_CONN_TTL = 3600 ## seconds (1 hour)
SNIFF_TIMEOUT = 60 # seconds
CONTEXT_TTL = 500 # seconds
        
'''
Type 3  - Destination Unreachable
Type 11 - Time Exceeded
Type 12 - Parameter Problem
Type 31 - Datagram Conversion Error (Deprecated)
Type 40 - Photuris
    Codes   Description 
    0       Bad SPI 
    1       Authentication Failed   
    2       Decompression Failed    
    3       Decryption Failed   
    4       Need Authentication 
    5       Need Authorization
'''
ICMP_ERR_TYPES = [3, 11, 12, 31, 40]

## LSTM parameters
LSTM_TIME_STEPS = 64 #128
LSTM_HIDDEN_SIZE = 500 #500
LSTM_NUM_EPOCHS = 100
LSTM_BATCH_SIZE = 256 #100
LSTM_DATA_DIM = 28 ## features
LSTM_FLOW_FEATURES = 12
LSTM_STATEFUL = True

## Normalized parameters
RATIO = 2
MAX_CONN = 1000
MAX_IP = 4294967295
MAX_PORT = 65535
MAX_PROTO = 255
MAX_TCP_FLAG = 4096 ## 12 bits
MAX_SRC_CONN = 277360*RATIO
MAX_DST_CONN = 277360*RATIO*MAX_CONN
## Accumulated stats
MAX_ACC_SRC_CONN = 424834*RATIO
MAX_ACC_DST_CONN = 424834*RATIO*MAX_CONN
## Traffic stats
MAX_RX_BYTES = 150124690*RATIO
MAX_TX_BYTES = 9319618*RATIO #need updated
MAX_RX_PACKETS = 21050*RATIO #need updated
MAX_TX_PACKETS = 21050*RATIO #need updated
## Context stats
MAX_CX_RX_BYTES = 96535*RATIO*MAX_CONN #96535760/1000
MAX_CX_TX_BYTES = 96498*RATIO*100 #96498791/1000
MAX_CX_RX_PACKETS = 12061*RATIO*MAX_CONN
MAX_CX_TX_PACKETS = 9864*RATIO*100

## Run options (should be command line arguments)
prev_time = 0
cur_time = 0
off_line = 1
run_option = 1 # 1: train, 2: deploy/test
training_time = 3600 # seconds
model_save_path = "/mnt/data/thomas/nids/v2/lstm_model.hdf5"
##############################################

def inet_to_int(ip_string):
    try:
        ip_struct = socket.inet_aton(ip_string)
        return struct.unpack("!L", ip_struct)[0]
    except ValueError:
        print("[inet_to_int] Failed to convert ip str to integer value!!!")

def build_key(ip):
    result = ''
    if TCP in ip:
	    result += str(inet_to_int(ip.src)) + str(inet_to_int(ip.dst))
	    tcp = ip[TCP]
	    result += str(tcp.sport)
	    result += str(tcp.dport)
    elif UDP in ip:
	    result += str(inet_to_int(ip.src)) + str(inet_to_int(ip.dst))
	    udp = ip[UDP]
	    result += str(udp.sport)
	    result += str(udp.dport)
    elif ICMP in ip:
	    icmp = ip[ICMP]
	    icmp_pkt = icmp.payload;
	    if icmp_pkt.haslayer("IP in ICMP"):
	        icmp_ip = icmp_pkt.getlayer("IP in ICMP");
	        result += str(inet_to_int(icmp_ip.src)) + str(inet_to_int(icmp_ip.dst))
	        if icmp_pkt.haslayer("UDP in ICMP"):
	            icmp_udp = icmp_pkt.getlayer("UDP in ICMP");
	            result += str(icmp_udp.sport)
	            result += str(icmp_udp.dport)
	        else:
	            result += '00'
	    else:
	        result += str(inet_to_int(ip.src)) + str(inet_to_int(ip.dst))
	        result += '00'
    else:
	    result += str(inet_to_int(ip.src)) + str(inet_to_int(ip.dst))
	    result += '00'
    return result
    
def build_reversed_key(ip):
    result = ''
    if TCP in ip:
	    result += str(inet_to_int(ip.dst)) + str(inet_to_int(ip.src))
	    tcp = ip[TCP]
	    result += str(tcp.dport)
	    result += str(tcp.sport)
    elif UDP in ip:
	    result += str(inet_to_int(ip.dst)) + str(inet_to_int(ip.src))
	    udp = ip[UDP]
	    result += str(udp.dport)
	    result += str(udp.sport)
    elif ICMP in ip:
	    icmp = ip[ICMP]
	    icmp_pkt = icmp.payload;
	    if icmp_pkt.haslayer("IP in ICMP"):
	        icmp_ip = icmp_pkt.getlayer("IP in ICMP");
	        result += str(inet_to_int(icmp_ip.dst)) + str(inet_to_int(icmp_ip.src))
	        if icmp_pkt.haslayer("UDP in ICMP"):
	            icmp_udp = icmp_pkt.getlayer("UDP in ICMP");
	            result += str(icmp_udp.dport)
	            result += str(icmp_udp.sport)
	        else:
	            result += '00'
	    else:
	        result += str(inet_to_int(ip.dst)) + str(inet_to_int(ip.src))
	        result += '00'
    else:
	    result += str(inet_to_int(ip.dst)) + str(inet_to_int(ip.src))
	    result += '00'
    return result
    
def is_a_new_flow(ip):
    if TCP in ip:
	    tcp = ip[TCP]
	    return (tcp.flags == dpkt.tcp.TH_SYN)
    return True
    
## Function to normalize input data to [0,1]
def get_norm_val(x, max_val):
    if x > max_val:
        print("max value needs updated from {} to {}".format(max_val,x))
        return 1
    if x < 0:
        return 0
    return (float)(x)/max_val
                                    
############################
if __name__ == '__main__':
    '''print(inet_to_int("255.255.255.255")) ## Max value: 4294967295
    r = (float)(1)/3
    print(r)
    data = np.random.random((1000, 100))
    labels = np.random.randint(2, size=(1000, 1))
    print(data.shape)
    print(labels.shape)
    
    matrix = np.zeros((2,3))
    arr1 = np.zeros(2)
    arr1[0] = 1
    arr1[1] = 2
    matrix[0,0:2] = arr1
    arr1[0] = 3
    arr1[1] = 4
    matrix[1,0:2] = arr1
    print(len(matrix))
    print(math.ceil((float)(2)/3))
    
    # load...
    data = list()
    n = 5000
    for i in range(n):
        data.append([i+1, (i+1)*10])
    data = np.array(data)
    print(data[:5, :])
    print(data.shape)
    
    # split into samples (e.g. 5000/200 = 25)
    samples = list()
    length = 200
    # step over the 5,000 in jumps of 200
    for i in range(0,n,length):
        # grab from i to i + 200
        sample = data[i:i+length]
        samples.append(sample)
    print(len(samples))

    # convert list of arrays into 2d array
    data = np.array(samples)
    print(data.shape)

    # reshape into [samples, timesteps, features]
    # expect [25, 200, 2]
    data = data.reshape((len(samples), length, 2))
    print(data.shape)
    print(data[:, :5, :])
    
    arr = np.empty(2, dtype=object)
    arr[0] = 'hello'
    arr[1] = 'world'
    print(arr)
    
    l = [1,2,3,4,5]
    #print(', '.join(str(x) for x in l))
    print(l[0])'''
    
    m = np.zeros((2,3,4))
    print('x:{}, y:{}'.format(len(m), len(m[0])))
    

