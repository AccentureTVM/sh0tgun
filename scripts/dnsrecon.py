#!/usr/bin/env python
import subprocess
import sys
import logging

def main(args):
	if len(args) != 3:
		logging.error("Usage: dnsrecon.py <ip address> <root>")
		return

	# ip_address = sys.argv[1]
	# HOSTNAME = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address)# grab the hostname
	# host = subprocess.check_output(HOSTNAME, shell=True).strip()
	# logging.info("Attempting Domain Transfer on " + host)
	# ZT = "dig @%s.thinc.local thinc.local axfr" % (host)
	# ztresults = subprocess.check_output(ZT, shell=True)
	# if "failed" in ztresults:
	#	 logging.info("Zone Transfer failed for " + host)
	# else:
	#	 print("[*] Zone Transfer successful for " + host + "(" + ip_address + ")!!! [see output file]")
	#	 outfile = "discovery/dns/" + ip_address+ "_zonetransfer.txt"
	#	 dnsf = open(outfile, "w")
	#	 dnsf.write(ztresults)
	#	 dnsf.close

	ip_address = args[1]
	root = args[2]
	try:
		host = "host " + ip_address
		host = subprocess.check_output(host, shell=True).strip()
		try:
			dnsrecon = "dnsrecon -d %s -t axfr" %(ip_address)
			dnsrecon = subprocess.check_output(dnsrecon, shell=True)
			dnsrecon = dnsrecon.decode('utf-8')
			logging.info ("DNSRecon run for " + ip_address + ". See " + root + "discovery/dns/ for results.")
			out = root + "discovery/dns/" + ip_address + "_dnsrecon.txt"
			dnsout = open(out, "w+")
			dnsout.write(dnsrecon)
			dnsout.close()
		except:
			logging.error ("DNSrecon failed for " + ip_address)
		
	except:
		logging.info ("No host found for " + ip_address)

if __name__=='__main__':
	main(sys.argv)
