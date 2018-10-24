#!/usr/bin/env python

from scapy.all import *
import argparse
import numpy as np
import fields_extractor as fe
import packets_summary as ps
import packets_reconstructor as pr
import inference_engine as ie
import multiprocessing as mp
import settings
import time

class Monitor:
	def __init__(self, interface, bg_traffic_fn, m2c_queue, c2m_queue):	
		self.interface = interface
		self.bg_traffic_fn = bg_traffic_fn ## Name of the background traffic file
		## Create a Packet Counter
		self.packet_counter = 0
		self.normalized_matrix = np.zeros((1,fe.NUM_HEADER_FIELDS))
		self.bg_traffic_index = 0 ## bg_traffic_index < len(settings.g_background_traffic[self.bg_traffic_fn])
		self.m2c_queue = m2c_queue ## monitor to central controller queue (report)
		self.c2m_queue = c2m_queue ## central controller to monitor queue (command)
		self.monitored_flows = []
		self.new_flows = []
		self.src_ips = []
		self.dst_ips = []
		self.workload = 0 ## Number of monitored packets per second
		self.workload_prev_time = time.time()
		self.cur_summary_id = 0
		self.saved_new_packets_list = [] ## List of list
		self.saved_new_packets = [] ## List of saved packets of the current summary id
		self.flows_last_active_time = {}
	
	## Extract flow info as a string from an ip packet
	def create_flow_str(self, ip):
		src_port = '0'
		dst_port = '0'
		
		if TCP in ip:
			tcp = ip[TCP]
			src_port = tcp.sport
			dst_port = tcp.dport
		if UDP in ip:
			udp = ip[UDP]
			src_port = udp.sport
			dst_port = udp.dport
		return (ip.src + '|' + str(src_port) + '|' + ip.dst + '|' + str(dst_port))
	
	## Extract flow info as a tuple from an ip packet
	def create_flow_tuple(self, ip):
		src_port = '0'
		dst_port = '0'
		flow = {}
		
		if TCP in ip:
			tcp = ip[TCP]
			src_port = tcp.sport
			dst_port = tcp.dport
		if UDP in ip:
			udp = ip[UDP]
			src_port = udp.sport
			dst_port = udp.dport
		flow['src'] = ip.src
		flow['src_port'] = src_port
		flow['dst'] = ip.dst
		flow['dst_port'] = dst_port
		return flow
	
	## Function used to handle a received packet
	def handle_received_packet(self, packet):	
		## Process the received packetself.saved_new_packets
		ip = packet[0][IP]
	
		flow_str = self.create_flow_str(ip)
		if flow_str in self.monitored_flows:
			self.flows_last_active_time[flow_str] = time.time()
				
			## Extract header fields of interest and normalize them
			norm_fields = fe.extract_normalized_fields(ip)
	
			## Append the normalized matrix with the current packet
			self.normalized_matrix = np.concatenate((self.normalized_matrix, [norm_fields]), axis=0)
	
			#print("-----------------------------------------")
			#ip.show()
			#print('Packet #{}: protocol={}, {} ==> {}'.format(self.packet_counter, ip.proto, ip.src, ip.dst))
	
			## Increment the global packet counter
			self.packet_counter += 1
	
			## Check if accumulate enough packets
			if self.packet_counter >= settings.BATCH_SIZE:
				self.perform_packets_summary()
		else:
			## Save the new packet
			self.saved_new_packets += [ip]
			
			## Append the new flow into the list self.new_flows 
			if flow_str not in self.new_flows:
				self.new_flows.append(flow_str)
			
			#if (ip.src in self.src_ips) or (ip.dst in self.dst_ips):
			## Perform statistics for related flows
	
	def cleanup_monitored_flows(self):
		i = 0
		cur_time = time.time()
		print('Process:{}, cleanup: number of monitored flows:{}, active flows:{}'.format(self.interface, len(self.monitored_flows), len(self.flows_last_active_time)))
		while i < len(self.monitored_flows):
			flow = self.monitored_flows[i]
			if flow in self.flows_last_active_time:
				if (cur_time - self.flows_last_active_time[flow]) >= settings.ACTIVE_TIMEOUT:
					## Remove the flow from self.monitored_flows
					del self.monitored_flows[i]
					## Remove the flow from self.flows_last_active_time
					del self.flows_last_active_time[flow]
				else:
					i += 1
			else:
				i += 1
	
	def handle_assigned_flows(self, flows):
		## Remove inactive flows from the monitored flows
		self.cleanup_monitored_flows()
		
		for flow in flows:
			## Update monitor flows (flow format: src|src_port|dst|dst_port)
			self.monitored_flows.append(flow)
		
			## Update IPs of interest
			flow_info = flow.split('|')
			self.src_ips.append(flow_info[0])
			self.dst_ips.append(flow_info[2])

	## Calculate work load in terms of number of monitored packets per second
	def cal_workload(self):
		cur_time = time.time()
		self.workload = self.packet_counter/(cur_time - self.workload_prev_time)

	def update_summary_id(self):
		self.cur_summary_id += 1
		if self.cur_summary_id >= settings.MAX_SUMMARY_ID:
			self.cur_summary_id = 0
	
	def update_saved_packets(self):
		item = {}
		item['packet_list'] = self.saved_new_packets
		item['summary_id'] = self.cur_summary_id
		self.saved_new_packets_list += [item]
		self.saved_new_packets = []
	
	def process_monitored_packets(self, packet_list):
		for ip in packet_list:
			flow_str = self.create_flow_str(ip)
			if flow_str in self.monitored_flows:
				self.flows_last_active_time[flow_str] = time.time()
				
				## Extract header fields of interest and normalize them
				norm_fields = fe.extract_normalized_fields(ip)
	
				## Append the normalized matrix with the current packet
				self.normalized_matrix = np.concatenate((self.normalized_matrix, [norm_fields]), axis=0)
	
				## Increment the global packet counter
				self.packet_counter += 1
		
	def handle_saved_packets(self, ack_summary_id):
		if len(self.saved_new_packets_list) > 0:
			self.normalized_matrix = np.zeros((1,fe.NUM_HEADER_FIELDS))
			self.packet_counter = 0
			index = 0
			
			## Process the packets of monitored flows
			while index < len(self.saved_new_packets_list):
				summary_id = self.saved_new_packets_list[index]['summary_id']
				packet_list = self.saved_new_packets_list[index]['packet_list']
				index += 1
				
				self.process_monitored_packets(packet_list)
				if summary_id == ack_summary_id:
					break
					
			## Remove the processed packets from the saved_new_packets_list
			del self.saved_new_packets_list[0:index]
			
			## Summarize the packets and send it to the central controller if needed
			if self.packet_counter >= settings.BATCH_SIZE:
				## Calculate current work load
				self.cal_workload()
				
				## Summarize the normalized packet matrix
				model, S, V = ps.PacketsSummary.summarize(settings.KMEAN_NUM_CLUSTERS, self.normalized_matrix[1:,:], settings.SVD_MATRIX_RANK)
				record = {}
				record['model'] = model
				record['S'] = S
				record['V'] = V
				record['flows'] = []
				record['load'] = self.workload
				record['flow_count'] = len(self.monitored_flows)
				record['summary_id'] = self.cur_summary_id
				print('Process:{}, saved_packets: flow_count:{}'.format(self.interface, len(self.monitored_flows)))
				
				## Report the packet summary, new flows, and current work load to the central controller
				self.m2c_queue.put(record)
				
				self.normalized_matrix = np.zeros((1,fe.NUM_HEADER_FIELDS))
				self.packet_counter = 0
	
	def perform_packets_summary(self):
		if self.packet_counter >= settings.MIN_REPORT_SIZE:
			## Calculate current work load
			self.cal_workload()
			self.update_saved_packets()
			
			## Summarize the normalized packet matrix
			model, S, V = ps.PacketsSummary.summarize(settings.KMEAN_NUM_CLUSTERS, self.normalized_matrix[1:,:], settings.SVD_MATRIX_RANK)
			record = {}
			record['model'] = model
			record['S'] = S
			record['V'] = V
			record['flows'] = self.new_flows
			record['load'] = self.workload
			record['flow_count'] = len(self.monitored_flows)
			record['summary_id'] = self.cur_summary_id
			print('Process:{}, summary: flow_count:{}, flows:{}'.format(self.interface, len(self.monitored_flows), len(self.new_flows)))
			## Report the packet summary, new flows, and current work load to the central controller
			self.m2c_queue.put(record)
	
			"""## Reconstruct the matrix
			reconstructed_matrix = pr.reconstruct_matrix(model.cluster_centers_, S, V, settings.SVD_MATRIX_RANK)
			#print("reconstructed_matrix:{}".format(reconstructed_matrix))
			infer = ie.InferenceEngine(model,reconstructed_matrix)
			infer.check_syn_flood()
			print("original:")
			check_syn_flag(self.normalized_matrix)
			print("reconstructed:")
			check_syn_flag(reconstructed_matrix)
			print("-----------------------------------------")"""
	
			## Reset the packet counter
			self.packet_counter = 0
			## Reset the normalized matrix
			self.normalized_matrix = np.zeros((1,fe.NUM_HEADER_FIELDS))
			self.new_flows = []
	
			## Check if the central controller has assigned new monitor flows
			command = self.c2m_queue.get()
			## Extract the flow strings and IPs of interest
			if 'flows' in command:
				self.handle_assigned_flows(command['flows'])
				
				## Handle the saved packets of newly assigned flows
				if 'summary_id' in command and len(command['flows']) > 0:
					self.handle_saved_packets(command['summary_id'])
	
			## Save the current time to calculate work load
			self.workload_prev_time = time.time()
			self.update_summary_id()
		
		## Preload background traffic
		self.preload_bg_traffic()

	## Read settings.BATCH_SIZE packets and collect all flows
	def get_initial_new_flows(self):
		flows = []
		for i in range(settings.BATCH_SIZE):
			ip = settings.g_background_traffic[self.bg_traffic_fn][i]
			flow_str = self.create_flow_str(ip)
			flows.append(flow_str)
		return flows

	## Preload settings.BG_TRAFFIC_SIZE packets from settings.g_background_traffic[self.bg_traffic_fn] to normalized_matrix
	def preload_bg_traffic(self):
		## Load background traffic
		#self.packet_counter = 0
		for i in range(settings.MAX_BG_TRAFFIC_TO_READ):
			ip = settings.g_background_traffic[self.bg_traffic_fn][self.bg_traffic_index]
			flow_str = self.create_flow_str(ip)
			
			## Update bg_traffic_index
			self.bg_traffic_index += 1
			if self.bg_traffic_index >= len(settings.g_background_traffic[self.bg_traffic_fn]):
				self.bg_traffic_index = 0
				print('Process:{}, reset bg_traffic_index'.format(self.interface))
			
			## Process the packet	
			if flow_str not in self.monitored_flows:
				## Save the new packet
				self.saved_new_packets += [ip]
			
				## Append the new flow into the list self.new_flows 
				if flow_str not in self.new_flows:
					self.new_flows.append(flow_str)
			
				#if (ip.src in self.src_ips) or (ip.dst in self.dst_ips):
				## Perform statistics for related flows
			else:
				## Extract header fields of interest and normalize them
				norm_fields = fe.extract_normalized_fields(ip)
				self.normalized_matrix = np.concatenate((self.normalized_matrix, [norm_fields]), axis=0)
				
				## Check if we have loaded enough background traffic
				self.packet_counter += 1
				if self.packet_counter >= settings.BG_TRAFFIC_SIZE:
					break

	## Padd the remaining rows of normalized_matrix with background traffic
	def perform_packets_padding(self):
		## Load background traffic
		#print("new_index:{},remainings:{},self.bg_traffic_index:{}".format(new_index,remainings,self.bg_traffic_index))
		for i in range(self.packet_counter,settings.BATCH_SIZE):
			ip = settings.g_background_traffic[self.bg_traffic_fn][self.bg_traffic_index]
			flow_str = self.create_flow_str(ip)
			self.bg_traffic_index += 1
			if self.bg_traffic_index >= len(settings.g_background_traffic[self.bg_traffic_fn]):
				self.bg_traffic_index = 0
			while flow_str not in self.monitored_flows:
				## Append the new flow into the list self.new_flows 
				self.new_flows.append(self.create_flow_tuple(ip))
			
				#if (ip.src in self.src_ips) or (ip.dst in self.dst_ips):
				## Perform statistics for related flows
				
				ip = settings.g_background_traffic[self.bg_traffic_fn][self.bg_traffic_index]
				flow_str = self.create_flow_str(ip)
				self.bg_traffic_index += 1
				if self.bg_traffic_index >= len(settings.g_background_traffic[self.bg_traffic_fn]):
					self.bg_traffic_index = 0
				
			## Extract header fields of interest and normalize them
			norm_fields = fe.extract_normalized_fields(ip)
			self.normalized_matrix[i] = norm_fields
	
	def monitor(self):
		initial_flows = self.get_initial_new_flows()
		## Send the initial flows to the central controller
		self.m2c_queue.put(initial_flows)
		
		print("Process {} is waiting for initial flow assignment...".format(self.interface))
		command = self.c2m_queue.get(True) ## Blocking get
		## Extract the flow strings and IPs of interest
		if 'flows' in command:
			self.handle_assigned_flows(command['flows'])
		else:
			print("Wrong command received at thread: {}, command: {}".format(self.interface, command))
		print("Process:{}, initial flows:{}".format(self.interface, len(self.monitored_flows)))
		
		## Save the current time to calculate work load
		self.workload_prev_time = time.time()
		
		## Preload background traffic
		self.preload_bg_traffic()
		
		print("Sniffing packet at {} ...".format(self.interface))
	
		## Setup sniff, filtering for IP traffic
		while True:
			## Sniff packets
			sniff(iface=self.interface, filter="ip", prn=self.handle_received_packet, store=0, timeout=settings.SNIFF_TIMEOUT)
		
			#print("Process:{}, sniff timeout".format(self.interface))
			
			## Timeout, we need to perform packets summary
			self.perform_packets_summary()
			
	def run(self):
		m = mp.Process(name=self.interface, target=self.monitor)
		m.start()
		

