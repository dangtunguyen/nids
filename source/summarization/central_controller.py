#!/usr/bin/env python

from scapy.all import *
import settings
import time
import packets_reconstructor as pr
import inference_engine as ie
import multiprocessing as mp
import fields_extractor as fe
import numpy as np


class CentralController:
	def __init__(self, m2c_queues, c2m_queues):
		self.packet_matrix = np.zeros((1,fe.NUM_HEADER_FIELDS))
		self.membership_count = np.zeros(1)
		self.m2c_queues = m2c_queues
		self.c2m_queues = c2m_queues
		self.num_monitors = len(m2c_queues)
		self.monitors_workload = np.zeros(self.num_monitors)
		self.monitors_flow_count = np.zeros(self.num_monitors)
		self.new_flows = {}
		self.latest_summary_ids = np.zeros(self.num_monitors) ## Store the latest summary id of each monitor
	
	def process_new_flows(self, flows, queue_id):
		for flow in flows:
			if flow not in self.new_flows:
				## Add the new flow to self.new_flows
				self.new_flows[flow] = [queue_id]
			else:
				## Update the mintor group of the existing flow
				monitors = self.new_flows[flow]
				if queue_id not in monitors:
					monitors += [queue_id]
	
	def get_average_flow_workload(self):
		num_flows = 0
		work_load = 0
		for i in range(self.num_monitors):
			num_flows += self.monitors_flow_count[i]
			work_load += self.monitors_workload[i]
		if num_flows > 0:
			return work_load/num_flows
		else:
			return 0
	
	def get_min_workload_monitor(self, monitors):
		m = monitors[0]
		min_load = self.monitors_workload[m]
		for i in range(1,len(monitors)):
			m1 = monitors[i]
			if min_load > self.monitors_workload[m1]:
				m = m1
				min_load = self.monitors_workload[m1]
		return m
	
	def perform_flow_assignment(self):
		## Calculate current average work load per flow
		average_load = self.get_average_flow_workload()
		
		## Initialize the flow assignments
		flow_assignments = [[] for i in range(self.num_monitors)]
		
		print('[Controller] number of new flows:{}'.format(len(self.new_flows)))
		
		## Perform assignment
		for flow, monitors in self.new_flows.iteritems():
			## Get the monitor in monitors with minimum workload
			m = self.get_min_workload_monitor(monitors)
			
			## Assign the current flow to m
			flow_assignments[m] += [flow]
			
			## Update workload of the selected monitor
			self.monitors_workload[m] += average_load
		
		## Send the assignment to the monitors
		for i in range(self.num_monitors):
			command = {}
			command['flows'] = flow_assignments[i]
			command['summary_id'] = self.latest_summary_ids[i]
			print("[Controller] # flows for monitor {}: {}".format(i, len(flow_assignments[i])))
			self.c2m_queues[i].put(command)
	
	def process_report_record(self, record, queue_id):
		if 'model' in record: ## A packet summary
			## Reconstruct the packet matrix
			matrix = pr.reconstruct_matrix(record['model'].cluster_centers_, record['S'], record['V'], settings.SVD_MATRIX_RANK)
			## Aggregate the summaries
			self.packet_matrix = np.concatenate((self.packet_matrix, matrix), axis=0)
			## Aggregate the membership count info
			self.membership_count = np.concatenate((self.membership_count,pr.get_membership_count(record['model'], len(matrix))), axis=0)
			
			## Gather new incoming flows
			self.process_new_flows(record['flows'], queue_id)
			
		#elif 'header' in record: ## Matrix of packet headers
			## Process packet headers
			
		## Extract work load info
		if 'load' in record:
			self.monitors_workload[queue_id] = record['load']
		else:
			print("[Controller] wrong record: {}".format(record))
		if 'flow_count' in record:
			self.monitors_flow_count[queue_id] = record['flow_count']
		else:
			print("[Controller] wrong record: {}".format(record))
		if 'summary_id' in record:
			self.latest_summary_ids[queue_id] = record['summary_id']
		else:
			print("[Controller] wrong record: {}".format(record))	
		
			
	def perform_intrusion_detection(self):
		if len(self.packet_matrix) > 1:
			infer = ie.InferenceEngine(self.packet_matrix[1:,:], self.membership_count[1:])
			infer.check_syn_flood()
			
	def initialize_class_variables(self):
		self.packet_matrix = np.zeros((1,fe.NUM_HEADER_FIELDS))
		self.membership_count = np.zeros(1)
		self.new_flows = {}
		
	def handle_initial_flow_assignment(self):
		## Collect initial flows from monitors
		for i in range(self.num_monitors):
			flows = self.m2c_queues[i].get(True)
			self.process_new_flows(flows, i)
		
		## Initialize the flow assignments
		self.monitors_workload = np.zeros(self.num_monitors)
		flow_assignments = [[] for i in range(self.num_monitors)]
		
		## Perform assignment
		for flow, monitors in self.new_flows.iteritems():
			## Get the monitor in monitors with minimum workload
			m = self.get_min_workload_monitor(monitors)
			
			## Assign the current flow to m
			flow_assignments[m] += [flow]
			
			## Update workload of the selected monitor
			self.monitors_workload[m] += 1
		
		## Send the assignment to the monitors
		for i in range(self.num_monitors):
			command = {}
			command['flows'] = flow_assignments[i]
			print("[Controller] # flows for monitor {}: {}".format(i, len(flow_assignments[i])))
			self.c2m_queues[i].put(command)
			
			
	def main_procedure(self):
		self.handle_initial_flow_assignment()
		
		while True:
			## Wait for AGGREGATION_TIMEOUT seconds
			time.sleep(settings.AGGREGATION_TIMEOUT)
			
			## Initialize class variables
			self.initialize_class_variables()
			
			## Iterate through self.m2c queues to collect reports
			for i in range(self.num_monitors):
				## Read all reports in the current queue
				while self.m2c_queues[i].empty() != True:
					## Read the record from the queue
					record = self.m2c_queues[i].get()
					
					## Process the current record
					self.process_report_record(record, i)
					
			## Perform intrusion detection
			self.perform_intrusion_detection()
			
			## Perform flow assignment
			self.perform_flow_assignment()
			
	def run(self):
		cc = mp.Process(name="central controller", target=self.main_procedure)
		cc.start()
					
