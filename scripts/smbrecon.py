#!/usr/bin/python
import sys
import subprocess
import logging

def main(args):
	if len(args) < 3:
		logging.error("Usage: smbrecon.py <ip address> <port> <root>")
		return

	ip = args[1]
	port = args[2]
	if len(args) == 4:
		root = args[3]
	else:
		root=""
	logging.info("Starting nbtscan on " + ip)
	NBTSCAN = "nbtscan -r %s" % (ip)
	try:
		nbtresults = subprocess.check_output(NBTSCAN.split(' '))
		nbtresults = nbtresults.decode("utf-8")
		if "Connection refused" not in nbtresults and "Connect error" not in nbtresults and "Connection reset" not in nbtresults:
			logging.found("NBTSCAN User accounts/domains found on " + ip + " check discovery/smb for results")
			resultsfile = root + "discovery/smb/" + ip + ":" + port + "_nbtscan.txt"
			f = open(resultsfile, "w+")
			f.write(nbtresults)
			f.close
	except:
		logging.error("NBTscan did not execute correctly for " + ip + ":"+port)
	
	logging.info("Starting enum4linux on " + ip)
	ENUM4LINUX = "enum4linux -a %s" % (ip)
	try:
		enumresults = subprocess.check_output(ENUM4LINUX.split(' '))
		enumresults = enumresults.decode("utf-8")
		if ("Connection refused" not in enumresults) and ("Connect error" not in enumresults) and ("Connection reset" not in enumresults):
			logging.found("ENUM4LINUX User accounts/domains found on " + ip + " check discovery/smb for results")
			resultsfile = root + "discovery/smb/" + ip + ":" + port + "_enum4linux.txt"
			f = open(resultsfile, "w+")
			f.write(enumresults)
			f.close
	except:
		logging.error("enum4linux did no execute correctly for " + ip + ":"+port)

	logging.info("Running nmap smb vuln scan on " + ip)
	nse = "nmap -Pn -n --open -p %s --script=smb-check-vulns --script-args=unsafe=1 %s" % (port, ip)
	try:
		nseresults = subprocess.check_output(nse.split(' '))
		nseresults = nseresults.decode('utf-8')
		lines = nseresults.split("\n")
		for line in lines:
			if "VULNERABLE" in line and "NOT VULNERABLE" not in line:
				logging.found("SMB VULN on " +ip+ ": " +line + " | check discovery/smb for full results")
				f = open(root+"findings.csv", "a+")
				f.write(ip,port,"smb","MS08-067", "NSE","")
				f.close()
		resultsfile = root + "discovery/smb/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseresults)
		f.close
	except:
		logging.error("NSE smb scan failed for " + ip + ":"+port)

if __name__=='__main__':
	main(sys.argv)



