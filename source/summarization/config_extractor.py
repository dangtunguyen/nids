#!/usr/bin/env python

import sys

class ConfigExtractor:
	def __init__(self, file_name):
		self.file_name = file_name ## File containing config info
		self.interfaces = [] ## List of ethernet interfaces of the monitors
		self.fnames = [] ## List of files containing background traffic
		self.iface_fnames = [] ## Contains background traffic file of each interface
		
		## Read and extract config ino
		self.read_file()
		
	def read_file(self):
		try:	
			with open(self.file_name, "r") as ins:
				for line in ins:
					l = line.split() ## interface filename
					
					if l[0] not in self.interfaces:
						self.interfaces += [l[0]]
						self.iface_fnames += [l[1]]
						
					if l[1] not in self.fnames:
						self.fnames += [l[1]]
					
		except IOError as e:
			print("[ConfigExtractor] I/O error({0}): {1}".format(e.errno, e.strerror))
