#!/usr/bin/env python
import subprocess
import sys
import os
import logging

def main(args):
	if len(args) !=4:
		logging.error("Usage: ftprecon.py <ip address> <port> <root>")
		return

	ip_address = args[1].strip()
	port = args[2].strip()
	root = args[3]
	logging.info("Performing nmap FTP script scan for " + ip_address + ":" + port)
	FTPSCAN = "nmap -sV -Pn --open -p " + port + " --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oA " + root + "discovery/ftp/" + ip_address + "_ftp " + ip_address
	try:
		results = subprocess.check_output(FTPSCAN, shell=True)
	except:
		logging.error("FTP NSE scan failed for " + ip_address + ":" + port)
		return
	#try:
	results = results.decode('utf-8')
	outfile = root + "discovery/ftp/" + ip_address + ":" + port + "_ftp.txt"
	lines = results.split("\n")
	for line in lines:
		if "Anonymous FTP login allowed" in line:
			logging.warning("Anonymous FTP Login on " + ip_address) 
			f = open(root+"findings.csv", "a+")
			f.write(ip_address + "," + port + ",ftp,Anonymous FTP,NSE,")
			f.close()
	f = open(outfile, "w")
	f.write(results)
	f.close
	#except:
	#	logging.error("FTP NSE scan succeeded, however post processing has failed for " + ip_address + ":" + port + "\n\t\tSee raw nmap scan results in " + root + "discovery/ftp/")

if __name__=='__main__':
	main(sys.argv)