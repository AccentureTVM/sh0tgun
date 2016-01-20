#!/usr/bin/env python
import subprocess
import sys


def main(args):
	if len(args) != 3:
		logging.error("Usage: sshrecon.py <ip address> <port>")
		return

	ip_address = args[1].strip()
	port = args[2].strip()

	# logging.info("Performing hydra ssh scan against " + ip_address)
	# HYDRA = "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /root/wordlists/rockyou.txt -f -o %sresults/ssh/%s_sshhydra.txt -u %s -s %s ssh" % (root, ip_address, ip_address, port)
	# try:
	#	 results = subprocess.check_output(HYDRA, shell=True)
	#	 resultarr = results.split("\n")
	#	 for result in resultarr:
	#		 if "login:" in result:
	# 		print("[*] Valid ssh credentials found: " + result )
	# except:
	#	 logging.info("No valid ssh credentials found")


if __name__=='__main__':
	main(sys.argv)