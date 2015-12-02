#!/usr/bin/env python
import subprocess
import sys


def main(args):
	if len(args) != 2:
		print("Usage: dnsrecon.py <ip address>")
		return

	# ip_address = sys.argv[1]
	# HOSTNAME = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address)# grab the hostname
	# host = subprocess.check_output(HOSTNAME, shell=True).strip()
	# print("INFO: Attempting Domain Transfer on " + host)
	# ZT = "dig @%s.thinc.local thinc.local axfr" % (host)
	# ztresults = subprocess.check_output(ZT, shell=True)
	# if "failed" in ztresults:
	#	 print("INFO: Zone Transfer failed for " + host)
	# else:
	#	 print("[*] Zone Transfer successful for " + host + "(" + ip_address + ")!!! [see output file]")
	#	 outfile = "discovery/dns/" + ip_address+ "_zonetransfer.txt"
	#	 dnsf = open(outfile, "w")
	#	 dnsf.write(ztresults)
	#	 dnsf.close

	ip_address = args[1]

	host = "host " + ip_address + " | grep -v 'not found'"
	try:
		host = subprocess.check_output(host, shell=True).strip()
		host = host.decode('utf-8')
		if host != "":
			dnsrecon = "dnsrecon -d %s -t axfr" %(ip_address)
			dnsrecon = subprocess.check_output(dnsrecon, shell=True)
			print ("DNSRecon run for %s" ) % (ip_address)
			out = "discover/dns/" + ip_address + "_dnsrecon.txt"
			dnsout = open(out, "w+")
			dnsout.write(dnsrecon)
			dnsout.close()
		else:
			print ("INFO: No host found for " + ip_address)
	except:
		print ("ERROR: DNSrecon failed for " + ip_address)

if __name__=='__main__':
	main(sys.argv)
