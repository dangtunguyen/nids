import numpy as np
from scipy import spatial
import fields_extractor as fe
import threading

class InferenceEngine:
	SYN_FLOOD_DIFF = 0.1
	SYN_FLOOD_COUNT = 100
	SYN_FLOOD_SIP_VAR = 10
	#########################################################################
	
	def __init__(self, packet_matrix, membership_count):
		self.packet_matrix = packet_matrix
		self.membership_count = membership_count
				
	def transform_query(self, q_vector, U, S):
		temp = np.dot(np.transpose(q_vector), U)
		return np.dot(temp, np.linalg.inv(np.diag(S)))

	def cosine_similarity(self, v1, v2):
		return np.dot(v1, v1) / (np.linalg.norm(v1) * np.linalg.norm(v2))

	def jaal_diff(self, q, v):
		# Implements the difference mechanism discussed in the paper
		diff_sum = 0
		count = 0
		for i in range(len(q)):
			if q[i] != -1:
				diff_sum += abs(q[i] - v[i])
				count+=1
		return diff_sum/count
	
	## Calculate variance of field_index in the matrix Q
	def cal_field_var(self, Q, freq_count, field_index):
		temp_list = []
		for i in range(len(Q)):
			temp_list += [Q[i][field_index] * freq_count[i]]
		return np.var(temp_list)

	def check_syn_flood(self):
		# This is how a query vector is created.
		# Ininitialize vector of -1's. Then fill in relavent field. This is signature for SYN flood
		query_vector = np.ones(fe.NUM_HEADER_FIELDS) * -1
		query_vector[fe.SYN_INDEX] = 1
		
		#print("matrix len:{}".format(len(self.packet_matrix)))
		#print("membership_count len:{}".format(len(self.membership_count)))
		count = 0
		Q = np.zeros((1,fe.NUM_HEADER_FIELDS))
		freq_count = np.zeros(1)
		## The first row always contains initial values, all 0. Thus, we should skip the first row
		for i in range(1,len(self.packet_matrix)):
			if self.jaal_diff(query_vector, self.packet_matrix[i,:]) <= self.SYN_FLOOD_DIFF:
				count += self.membership_count[i]
				Q = np.concatenate((Q, [self.packet_matrix[i,:]]), axis=0)
				freq_count = np.concatenate((freq_count, [self.membership_count[i]]), axis=0)
		#print("sync flood count:{}, total:{}".format(count,len(self.packet_matrix)))
		
		## Check syn flood attack condition
		syn_flood = False
		if count >= self.SYN_FLOOD_COUNT:
			syn_flood = True
		
		## Check DDoS condition
		ddos = False
		if len(Q) > 1:
			sip_var = self.cal_field_var(Q[1:,:], freq_count[1:], fe.SIP_INDEX)
			print("[inference_engine] count:{}, sip_var:{}".format(count, sip_var))
			if sip_var >= self.SYN_FLOOD_SIP_VAR:
				ddos = True
		
		return syn_flood,ddos
