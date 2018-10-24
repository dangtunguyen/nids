#!/usr/bin/env python

from scapy.all import *
import argparse
import background_traffic as traffic
import config_extractor as ce
import monitor
import central_controller as cc
import settings
import multiprocessing as mp

def parse_args():
	## Define command-line arguments
	parser = argparse.ArgumentParser(description='Program used to monitor traffic at an ingress router.')
	parser.add_argument('-ifaces', nargs='+', 
		help='Interface where traffic is monitored', required=True)
	parser.add_argument('-fname', nargs=1, 
		help='Name of the background traffic file', required=True)
	## Parse command-line arguments
	return parser.parse_args()

def start_up(cf_filename):
	config = ce.ConfigExtractor(cf_filename)
	
	for filename in config.fnames:
		## Load background traffic
		print("Loading background traffic from {} ...".format(filename))
		bg_traffic = traffic.BackgroundTraffic(filename)
		settings.g_background_traffic[filename] = bg_traffic.load()
		print("Number of IP packets loaded from {}: {}".format(filename,len(settings.g_background_traffic[filename])))	
	
	## Return the config info
	return config
	
if __name__ == '__main__':
	## Load background traffics and get monitored interfaces
	config = start_up('config.txt')
	
	if len(config.interfaces) > 0:
		## List containing queues used by monitors to report their summary and new incoming flows
		m2c_queues = [] ## m2c: montior to the central controller
		## List containing queues used by central controller to assign flows to monitors
		c2m_queues = [] ## c2m: central controller to montior

		## Create and start up the monitor threads
		for i in range(len(config.interfaces)):
			m2c_queue = mp.Queue()
			c2m_queue = mp.Queue()
			m2c_queues += [m2c_queue]
			c2m_queues += [c2m_queue]
			m = monitor.Monitor(config.interfaces[i], config.iface_fnames[i], m2c_queue,c2m_queue)
			m.run()
		
		## Create and start the central controller thread
		controller = cc.CentralController(m2c_queues, c2m_queues)
		controller.run()
	
	
	
	
