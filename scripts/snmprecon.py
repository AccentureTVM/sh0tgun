#!/usr/bin/env python
import subprocess
import sys

def main(args):
	if len(args) != 2:
		print("Usage: snmprecon.py <ip address>")
		return

	snmpdetect = 0
	ip_address = args[1]

	ONESIXONESCAN = "onesixtyone %s" % (ip_address)
	
	try:
		results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()
		results = results.decode('utf-8')
		if results != "":
			if "Windows" in results:
				results = results.split("Software: ")[1]
				snmpdetect = 1
			elif "Linux" in results:
				results = results.split("[public] ")[1]
				snmpdetect = 1
			if snmpdetect == 1:
				print("INFO: SNMP running on " + ip_address + "; OS Detect: " + results)
				SNMPWALK = "snmpwalk -c public -v1 %s 1 > " + root + "discovery/snmp/%s_snmpwalk.txt" % (ip_address, ip_address)
				try:
					results = subprocess.check_output(SNMPWALK, shell=True)
				except:
					print("ERROR: Snmpwalk scan failed for " + ip + ":" + port)
	except:
		print("ERROR: Onesixtyone scan failed for " + ip + ":" + port)

if __name__=='__main__':
	main(sys.argv)
