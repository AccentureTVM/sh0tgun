#!/usr/bin/env python
import subprocess
import sys
import os

def main(args):
	if len(args) !=4:
		print("Usage: ftprecon.py <ip address> <port> <root>")
		return

	ip_address = args[1].strip()
	port = args[2].strip()
	root = args[3]
	print("INFO: Performing nmap FTP script scan for " + ip_address + ":" + port)
	FTPSCAN = "nmap -sV -Pn --open -p " + port + " --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oA " + root + "discovery/ftp/" + ip_address + "_ftp " + ip_address
	try:
		results = subprocess.check_output(FTPSCAN, shell=True)
		outfile = root + "discovery/ftp/" + ip_address + "_ftp.txt"
		lines = results.split("\n")
		for line in lines:
			if "Anonymous FTP login allowed" in line:
				print("FOUND: Anonymous FTP Login on " + ip_address) 
		f = open(outfile, "w")
		f.write(results)
		f.close
	except:
		print("ERROR: FTP NSE scan failed for " + ip_address + ":" + port)

if __name__=='__main__':
	main(sys.argv)