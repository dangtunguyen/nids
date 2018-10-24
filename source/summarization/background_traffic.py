#!/usr/bin/env python

from scapy.all import *
import settings

class BackgroundTraffic:
	def __init__(self, filename):
		self.filename = filename
		self.background_traffic = []
		
	## Normalize each packet and append it to g_background_traffic
	def handle_packet(self, packet):
		if IP in packet[0]:
			## Process the current packet
			ip = packet[0][IP]
			#print('Protocol={}, {} ==> {}'.format(ip.proto, ip.src, ip.dst))
	
			## Append the traffic buffer with the current packet
			self.background_traffic += [ip]

	## Load background traffic from filename
	def load(self):
		self.background_traffic = []
		sniff(offline=self.filename, filter="ip", prn=self.handle_packet, store=0)
		return self.background_traffic

