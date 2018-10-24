#!/usr/bin/env python

from scapy.all import *
import numpy as np
import utils
import flow_stats
import context_stats
import lstm_model_builder as mb
from time import time
from collections import OrderedDict
from keras.models import load_model
import logging

class StatsManager:
    def __init__(self, interface):
    	#logging.basicConfig(filename='flow_stats.log',level=logging.DEBUG)
    	#logging.basicConfig(filename='classification.log',level=logging.DEBUG)
    	
        ## The monitored NIC interface
        self.interface = interface
        
        '''
        Key: flow tuple (src_ip | dst_ip | src_port | dst_port)
        Value: FlowStats
        '''
        self.flows_stats = {}
        
        ## List of flow keys which needs cleaned up
        self.rm_fs_keys = []
        
        '''
        Key: ip_addr
        Value: ContextStats
        '''
        self.context_stats = {}
        
        '''
        Dictionary of context keys needs cleaned up
        Key: ip_addr
        Value: time when the last flow is removed
        '''
        self.rm_cs_keys = OrderedDict()
        
        '''## Attribute to get max values of features
        # Flow stats
        self.max_tx_bytes = 0
        self.max_tx_packets = 0
        self.max_rx_bytes = 0
        self.max_rx_packets = 0
        # Context stats
        self.max_cx_tx_bytes = 0
        self.max_cx_tx_packets = 0
        self.max_cx_rx_bytes = 0
        self.max_cx_rx_packets = 0
        ## Connection counts
        self.max_src_connections = 0
        self.max_dst_connections = 0
        self.max_accu_src_connections = 0
        self.max_accu_dst_connections = 0'''
        
        self.lstm_model = None
        #self.prev_time = 0
        
    def create_or_update(self, ip):
        key = utils.build_key(ip)
        rkey = utils.build_reversed_key(ip)
        if (key in self.flows_stats) or (rkey in self.flows_stats):
            ## Existing flow
            fs = None
            if key in self.flows_stats:
                fs = self.flows_stats[key]
            else:
                fs = self.flows_stats[rkey]
            fs.update_stats(ip)
            self.update_traffic_stats(ip)
        elif utils.is_a_new_flow(ip):
            ## A new flow
            fs = flow_stats.FlowStats(ip)
            self.flows_stats[key] = fs
            self.create_or_update_context_stats(ip)
           
    def create_or_update_context_stats(self, ip):
        src_cs = None
        if ip.src in self.context_stats:
            src_cs = self.context_stats[ip.src]
        else:
            src_cs = context_stats.ContextStats(ip.src)
        src_cs.update_connections_stats(ip)
        self.context_stats[ip.src] = src_cs
        
        dst_cs = None
        if ip.dst in self.context_stats:
            dst_cs = self.context_stats[ip.dst]
        else:
            dst_cs = context_stats.ContextStats(ip.dst)
        dst_cs.update_connections_stats(ip)
        self.context_stats[ip.dst] = dst_cs
        
        if ip.src in self.rm_cs_keys:
            ## We should keep the context info of this ip_addr
            del self.rm_cs_keys[ip.src]
            
        if ip.dst in self.rm_cs_keys:
            ## We should keep the context info of this ip_addr
            del self.rm_cs_keys[ip.dst]
        
    def update_traffic_stats(self, ip):
        if ip.src in self.context_stats:
            self.context_stats[ip.src].update_traffic_stats(ip)
        if ip.dst in self.context_stats:
            self.context_stats[ip.dst].update_traffic_stats(ip)

    def incr_errors_stats(self):
        for fs in self.flows_stats.itervalues():
            if fs.is_erroneous() and fs.brand_new:
                #fs.print_stats()
                if fs.src_ip_str in self.context_stats:
                    self.context_stats[fs.src_ip_str].src_errors += 1
                    self.context_stats[fs.src_ip_str].accu_src_errors += 1
                if fs.dst_ip_str in self.context_stats:
                    self.context_stats[fs.dst_ip_str].dst_errors += 1
                    self.context_stats[fs.dst_ip_str].accu_dst_errors += 1

    def decr_errors_stats(self, fs):
        if fs.is_erroneous():
            if fs.src_ip_str in self.context_stats:
                self.context_stats[fs.src_ip_str].src_errors -= 1
                if self.context_stats[fs.src_ip_str].src_errors < 0:
                    self.context_stats[fs.src_ip_str].src_errors = 0
            if fs.dst_ip_str in self.context_stats:
                self.context_stats[fs.dst_ip_str].dst_errors -= 1
                if self.context_stats[fs.dst_ip_str].dst_errors < 0:
                    self.context_stats[fs.dst_ip_str].dst_errors = 0
    
    def get_data_dim(self):
        rows = math.ceil((float)(len(self.flows_stats))/(utils.LSTM_TIME_STEPS*utils.LSTM_BATCH_SIZE))
        rows = rows*utils.LSTM_TIME_STEPS*utils.LSTM_BATCH_SIZE
        return (int)(rows), (int)(utils.LSTM_DATA_DIM)
    
    ## return a list of flow stats, which is list of integers
    def get_stats(self):
        self.incr_errors_stats()
        self.rm_fs_keys = []
        rows, cols = self.get_data_dim()
        flows = np.zeros((rows, cols))
        flow_tuples = []
        labels = np.zeros(rows)
        i = 0
        for key,fs in self.flows_stats.iteritems():
            #fs.print_stats()
            '''## Calculate max values of featuresself.incr_errors_stats()
            if self.max_tx_bytes < fs.tx_bytes:
                self.max_tx_bytes = fs.tx_bytes
                print("max_tx_bytes:{}".format(self.max_tx_bytes))
            if self.max_rx_bytes < fs.rx_bytes:
                self.max_rx_bytes = fs.rx_bytes
                print("max_rx_bytes:{}".format(self.max_rx_bytes))
            if self.max_tx_packets < fs.tx_packets:
                self.max_tx_packets = fs.tx_packets
                print("max_tx_packets:{}".format(self.max_tx_packets))
            if self.max_rx_packets < fs.rx_packets:
                self.max_rx_packets = fs.rx_packets
                print("max_rx_packets:{}".format(self.max_rx_packets))'''
            
            flow = np.zeros(cols)   
            flow[0:utils.LSTM_FLOW_FEATURES] = fs.get_stats()
            
            ## src IP stats
            error_ratio = 0
            if self.context_stats[fs.src_ip_str].src_connections > 0:
                error_ratio = (float)(self.context_stats[fs.src_ip_str].src_errors)/self.context_stats[fs.src_ip_str].src_connections
            flow[utils.LSTM_FLOW_FEATURES+0] = error_ratio
            flow[utils.LSTM_FLOW_FEATURES+1] = utils.get_norm_val(self.context_stats[fs.src_ip_str].src_connections, utils.MAX_SRC_CONN)
            ## accumulated stats
            error_ratio = 0
            if self.context_stats[fs.src_ip_str].accu_src_connections > 0:
                error_ratio = (float)(self.context_stats[fs.src_ip_str].accu_src_errors)/self.context_stats[fs.src_ip_str].accu_src_connections
            flow[utils.LSTM_FLOW_FEATURES+2] = error_ratio
            flow[utils.LSTM_FLOW_FEATURES+3] = utils.get_norm_val(self.context_stats[fs.src_ip_str].accu_src_connections, utils.MAX_ACC_SRC_CONN)
            ## traffic stats
            flow[utils.LSTM_FLOW_FEATURES+4] = utils.get_norm_val(self.context_stats[fs.src_ip_str].rx_bytes, utils.MAX_CX_RX_BYTES)
            flow[utils.LSTM_FLOW_FEATURES+5] = utils.get_norm_val(self.context_stats[fs.src_ip_str].rx_packets, utils.MAX_CX_RX_PACKETS)
            flow[utils.LSTM_FLOW_FEATURES+6] = utils.get_norm_val(self.context_stats[fs.src_ip_str].tx_bytes, utils.MAX_CX_TX_BYTES)
            flow[utils.LSTM_FLOW_FEATURES+7] = utils.get_norm_val(self.context_stats[fs.src_ip_str].tx_packets, utils.MAX_CX_TX_PACKETS)
            ## 8 features
            
            ## dst IP stats
            error_ratio = 0
            if self.context_stats[fs.dst_ip_str].dst_connections > 0:
                error_ratio = (float)(self.context_stats[fs.dst_ip_str].dst_errors)/self.context_stats[fs.dst_ip_str].dst_connections    
            flow[utils.LSTM_FLOW_FEATURES+8] = error_ratio
            flow[utils.LSTM_FLOW_FEATURES+9] = utils.get_norm_val(self.context_stats[fs.dst_ip_str].dst_connections, utils.MAX_DST_CONN)
            ## accumulated stats
            error_ratio = 0
            if self.context_stats[fs.dst_ip_str].accu_dst_connections > 0:
                error_ratio = (float)(self.context_stats[fs.dst_ip_str].accu_dst_errors)/self.context_stats[fs.dst_ip_str].accu_dst_connections    
            flow[utils.LSTM_FLOW_FEATURES+10] = error_ratio
            flow[utils.LSTM_FLOW_FEATURES+11] = utils.get_norm_val(self.context_stats[fs.dst_ip_str].accu_dst_connections, utils.MAX_ACC_DST_CONN)
            ## traffic stats
            flow[utils.LSTM_FLOW_FEATURES+12] = utils.get_norm_val(self.context_stats[fs.dst_ip_str].rx_bytes, utils.MAX_CX_RX_BYTES)
            flow[utils.LSTM_FLOW_FEATURES+13] = utils.get_norm_val(self.context_stats[fs.dst_ip_str].rx_packets, utils.MAX_CX_RX_PACKETS)
            flow[utils.LSTM_FLOW_FEATURES+14] = utils.get_norm_val(self.context_stats[fs.dst_ip_str].tx_bytes, utils.MAX_CX_TX_BYTES)
            flow[utils.LSTM_FLOW_FEATURES+15] = utils.get_norm_val(self.context_stats[fs.dst_ip_str].tx_packets, utils.MAX_CX_TX_PACKETS)
            ## 8 features
            
            ## append to the result list
            flows[i,:] = flow
            if utils.run_option == 2:
                flow_tuples.append(fs.get_flow_tuple())
            else:
                labels[i] = fs.get_label();
            i += 1
            #print("flow stats:{}".format(flow))
            #logging.info('%s, %s, %d, %d: %s', fs.src_ip_str, fs.dst_ip_str, fs.src_port, fs.dst_port, ', '.join(str(x) for x in flow))
            
            ## Save stale/closed flows
            if fs.is_stale() or fs.is_conn_closed():
                ## Clean up the flows_stats
                self.rm_fs_keys.append(key)
                
                ## Clean up the context_stats:
                ## Check if the context error stats should be decremented
                ## due to the removal of the current flow
                self.decr_errors_stats(fs)
                ## Decrement connection stats
                self.context_stats[fs.src_ip_str].src_connections -= 1
                self.context_stats[fs.dst_ip_str].dst_connections -= 1
                ## If no connection from/towards src_ip_str/dst_ip_str,
                ## mark the ip_addr and save current time. This record will
                ## be removed from context_stats after some time
                t = 0
                if utils.off_line == 1:
                    t = utils.cur_time
                else:
                    t = time()
                if self.context_stats[fs.src_ip_str].src_connections <= 0 and self.context_stats[fs.src_ip_str].dst_connections <= 0:
                    self.context_stats[fs.src_ip_str].src_connections = 0 
                    self.context_stats[fs.src_ip_str].dst_connections = 0
                    ## Remove the key from rm_cs_keys before putting it into dictionary
                    ## so that the time order is maintained correctly
                    if fs.src_ip_str in self.rm_cs_keys:
                        del self.rm_cs_keys[fs.src_ip_str]
                    self.rm_cs_keys[fs.src_ip_str] = t
                if self.context_stats[fs.dst_ip_str].src_connections <= 0 and self.context_stats[fs.dst_ip_str].dst_connections <= 0:
                    self.context_stats[fs.dst_ip_str].src_connections = 0 
                    self.context_stats[fs.dst_ip_str].dst_connections = 0
                    ## Remove the key from rm_cs_keys before putting it into dictionary
                    ## so that the time order is maintained correctly
                    if fs.dst_ip_str in self.rm_cs_keys:
                        del self.rm_cs_keys[fs.dst_ip_str]
                    self.rm_cs_keys[fs.dst_ip_str] = t
            
        #self.print_context_stats()
        self.reset_context_stats()
        print("context stats size:{}".format(len(self.context_stats)))
        print("flows size:{}".format(flows.shape))
        if utils.run_option == 2:
            return flows, flow_tuples
        else:
            return flows, labels
    
    ## Remove a flow from DB if the connection is closed
    ## or the flow is stale
    def clean_up_db(self):
        ## Clean up the flows_stats
        for key in self.rm_fs_keys:
            del self.flows_stats[key]
        
        ## Clean up context_stats
        rm_keys = []
        t = 0
        if utils.off_line == 1:
            t = utils.cur_time
        else:
            t = time()
        for ip_addr,t1 in self.rm_cs_keys.iteritems():
            if (t-t1) > utils.CONTEXT_TTL:
                rm_keys.append(ip_addr)
                del self.context_stats[ip_addr]
            else:
                ## We don't need to go further since the dictionary has
                ## time order
                break
        ## Since we have removed those keys from self.context_stats,
        ## we should remove them from self.rm_cs_keys
        for key in rm_keys:
            del self.rm_cs_keys[key]
            
    def reset_context_stats(self):
        for cs in self.context_stats.itervalues():
            cs.reset_stats()
        
    def handle_received_packet(self, packet):
        ip = packet[0][IP]
        #print("src_ip: {}, dst_ip: {}".format(ip.src, ip.dst))
        self.create_or_update(ip)
    
    def create_train_data(self, flows, labels):
    	# 3D tensor with shape (batch_size, timesteps, input_dim).
        #trainX = np.random.random((num_rows, timesteps, data_dim))
        num_samples = len(flows)/utils.LSTM_TIME_STEPS
        trainX = flows.reshape(num_samples, utils.LSTM_TIME_STEPS, utils.LSTM_DATA_DIM)
        trainY = labels.reshape(num_samples, utils.LSTM_TIME_STEPS, 1)
        #trainY = np.zeros((num_samples,utils.LSTM_TIME_STEPS, 1)) # Assume all flows are normal
        #trainY = np.zeros(num_samples) # Assume all flows are normal
        return trainX, trainY
        
    def prepare_test_data(self, flows):
        num_samples = len(flows)/utils.LSTM_TIME_STEPS
        testX = flows.reshape(num_samples, utils.LSTM_TIME_STEPS, utils.LSTM_DATA_DIM)
        return testX
        
    def print_predict_results(self, testX, labels, flow_tuples):
        n = len(flow_tuples)
        x_dim = len(labels)
        y_dim = len(labels[0])
        for r in xrange(x_dim):
            for c in xrange(y_dim):
                index = r*y_dim + c
                if index < n:
                    stats = ', '.join(str(x) for x in testX[r][c])
                    logging.info('%s, label: %f, stats: %s', flow_tuples[index], labels[r][c][0], stats)
                else:
                    break
        
    def run(self):
        lstm_model = None
        start_time = time()
        if utils.run_option == 1:
            ## Training mode
            print("Training mode...")
            lstm_model = mb.LstmModelBuilder(utils.LSTM_BATCH_SIZE, utils.LSTM_TIME_STEPS, utils.LSTM_DATA_DIM, utils.LSTM_STATEFUL, utils.LSTM_NUM_EPOCHS, utils.LSTM_HIDDEN_SIZE, utils.model_save_path)
        elif utils.run_option == 2:
            ## Deployment mode
            print("Deployment mode...")
            lstm_model = load_model(utils.model_save_path)
            if lstm_model is None:
                print("Failed to load model from {}".format(utils.model_save_path))
                exit()
        else:
            print("Unexpected running mode")
            exit()
            
        ## Setup sniff, filtering for IP traffic
        while True:
            ## Sniff packets
            sniff(iface=self.interface, filter="ip", prn=self.handle_received_packet, store=0, timeout=utils.SNIFF_TIMEOUT)
            
            ################### Timeout, perform analysis ################
            if utils.run_option == 1:
                ## First, get stats
                flows, labels = self.get_stats()
                
                ## Training mode
                ## Second, prepare the input for LSTM model
                trainX, trainY = self.create_train_data(flows, labels)
                lstm_model.train(trainX, trainY)
                
                if (time()-start_time) > utils.training_time:
                    lstm_model.save()
                    print("Finish training the LSTM model")
                    exit()
            elif utils.run_option == 2:
                ## First, get stats
                flows, flow_tuples = self.get_stats()
            
                ## Deployment mode
                ## Second, prepare the input for LSTM model
                testX = self.prepare_test_data(flows)
                labels = lstm_model.predict(testX, batch_size=utils.LSTM_BATCH_SIZE)
                #print(labels.shape)
                #print("classified labels:{}".format(labels))
                self.print_predict_results(testX, labels, flow_tuples)
                
            ## Third, run LSTM model with each flow stats
            
            ## Fourth, report the result
            
            ## Fifth, clean up the DB
            self.clean_up_db()
            
    def handle_offline_packet(self, packet):
        utils.cur_time = packet[0].time
        if IP in packet[0]:
            ## Process the current packet
            ip = packet[0][IP]
            
            #print(packet[0].time)

            #print("src_ip: {}, dst_ip: {}".format(ip.src, ip.dst))
            self.create_or_update(ip)

            if (packet[0].time - utils.prev_time) >= utils.SNIFF_TIMEOUT:
                self.process_packets_batch()
                utils.prev_time = packet[0].time
        
    def process_packets_batch(self):
        ################### Timeout, perform analysis ################
        if utils.run_option == 1:
            ## First, get stats
            flows, labels = self.get_stats()
            
            print(labels)
            
            ## Training mode
            ## Second, prepare the input for LSTM model
            trainX, trainY = self.create_train_data(flows, labels)
            self.lstm_model.train(trainX, trainY)
        elif utils.run_option == 2:
            ## First, get stats
            flows, flow_tuples = self.get_stats()
        
            ## Deployment mode
            ## Second, prepare the input for LSTM model
            testX = self.prepare_test_data(flows)
            labels = self.lstm_model.predict(testX, batch_size=utils.LSTM_BATCH_SIZE)
            #print(labels.shape)
            #print("classified labels:{}".format(labels))
            self.print_predict_results(testX, labels, flow_tuples)
            
        ## Third, run LSTM model with each flow stats
        
        ## Fourth, report the result
        
        ## Fifth, clean up the DB
        self.clean_up_db()
            
    def run_offline(self, traffic_file):
        # load or create LSTM model
        if utils.run_option == 1:
            ## Training mode
            print("Training mode...")
            self.lstm_model = mb.LstmModelBuilder(utils.LSTM_BATCH_SIZE, utils.LSTM_TIME_STEPS, utils.LSTM_DATA_DIM, utils.LSTM_STATEFUL, utils.LSTM_NUM_EPOCHS, utils.LSTM_HIDDEN_SIZE, utils.model_save_path)
        elif utils.run_option == 2:
            ## Deployment mode
            print("Deployment mode...")
            self.lstm_model = load_model(utils.model_save_path)
            if self.lstm_model is None:
                print("Failed to load model from {}".format(utils.model_save_path))
                exit()
        else:
            print("Unexpected running mode")
            exit()
        
        # process the traffic offline
        sniff(offline=traffic_file, filter="ip", prn=self.handle_offline_packet, store=0)
        
        self.process_packets_batch()
        
        # save the LSTM model if in training mode
        if utils.run_option == 1:
            self.lstm_model.save()
            print("Finish training the LSTM model")
	
    def print_context_stats(self):
        for cs in self.context_stats.itervalues():
            '''## Calculated max values of features
            if self.max_cx_tx_bytes < cs.tx_bytes:
                self.max_cx_tx_bytes = cs.tx_bytes
                print("max_cx_tx_bytes:{}".format(self.max_cx_tx_bytes))
            if self.max_cx_rx_bytes < cs.rx_bytes:
                self.max_cx_rx_bytes = cs.rx_bytes
                print("max_cx_rx_bytes:{}".format(self.max_cx_rx_bytes))
            if self.max_cx_tx_packets < cs.tx_packets:
                self.max_cx_tx_packets = cs.tx_packets
                print("max_cx_tx_packets:{}".format(self.max_cx_tx_packets))
            if self.max_cx_rx_packets < cs.rx_packets:
                self.max_cx_rx_packets = cs.rx_packets
                print("max_cx_rx_packets:{}".format(self.max_cx_rx_packets))
            if self.max_src_connections < cs.src_connections:
                self.max_src_connections = cs.src_connections
                print("max_src_connections:{}".format(self.max_src_connections))
            if self.max_dst_connections < cs.dst_connections:
                self.max_dst_connections = cs.dst_connections
                print("max_dst_connections:{}".format(self.max_dst_connections))
            if self.max_accu_src_connections < cs.accu_src_connections:
                self.max_accu_src_connections = cs.accu_src_connections
                print("max_accu_src_connections:{}".format(self.max_accu_src_connections))
            if self.max_accu_dst_connections < cs.accu_dst_connections:
                self.max_accu_dst_connections = cs.accu_dst_connections
                print("max_accu_dst_connections:{}".format(self.max_accu_dst_connections))'''
                
            logging.info('ip:%s,tx_bytes:%d,tx_packets:%d,rx_bytes:%d,rx_packets:%d,src_conn:%d,dst_conn:%d,src_errors:%d,dst_errors:%d,accu_src_conn:%d,accu_dst_conn:%d,accu_src_errors:%d,accu_dst_errors:%d', cs.ip_addr, cs.tx_bytes, cs.tx_packets, cs.rx_bytes, cs.rx_packets, cs.src_connections, cs.dst_connections, cs.src_errors, cs.dst_errors, cs.accu_src_connections, cs.accu_dst_connections, cs.accu_src_errors, cs.accu_dst_errors)
			
            '''if cs.src_errors > 0 or cs.dst_errors > 0:
                cs.print_stats()'''
			                
###########################################################
def handle_received_packet2(packet):   
    ## Process the received packetself.saved_new_packets
    ip = packet[0][IP]
    if ICMP in ip:
        icmp = ip[ICMP]
        print("-----------------------------------------")
        icmp.show()
        icmp_pkt = icmp.payload;
        if icmp_pkt.haslayer("IP in ICMP"):
            print("****")
            ip1 = icmp_pkt.getlayer("IP in ICMP")
            ip1.show()
        if icmp_pkt.haslayer("UDP in ICMP"):
            print("............")
            udp = icmp_pkt.getlayer("UDP in ICMP")
            udp.show()

def handle_received_packet1(packet):   
    ## Process the received packetself.saved_new_packets
    if IP in packet[0]:
        print(packet[0].time) #1538691512.64, 1538691512.66
    '''ip = packet[0][IP]
    if ICMP in ip:
        print("-----------------------------------------")
        print("key:{}".format(utils.build_key(ip)))
        print("reversed key:{}".format(utils.build_reversed_key(ip)))'''

if __name__ == '__main__':
    sm = StatsManager("wlan0")
    sm.run_offline("/mnt/data/thomas/nids/v2/traffic.pcap")
    #sniff(offline="/home/testbed/Desktop/Thomas/Stats/traffic.pcap", filter="ip", prn=handle_received_packet1, store=0)
    print('end!!!')
        

