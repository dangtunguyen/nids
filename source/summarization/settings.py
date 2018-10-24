#!/usr/bin/env python

## Global macros
SNIFF_TIMEOUT = 5
AGGREGATION_TIMEOUT = 5
ACTIVE_TIMEOUT = 20 ## If a flow doesn't have a packet traversing a router during ACTIVE_TIMEOUT, it will be removed from monitored flows
BATCH_SIZE = 1000
MAX_BG_TRAFFIC_TO_READ = 5000
MIN_REPORT_SIZE = 600 ## Only send summary report if number of traversing packets greater than this threshold
BG_TRAFFIC_SIZE = 900 ## Background traffic
SVD_MATRIX_RANK = 12 ## NUM_HEADER_FIELDS = 22
KMEAN_NUM_CLUSTERS = 200
MAX_SUMMARY_ID = 100


## Global variables
## List containing background traffic
g_background_traffic = {}
