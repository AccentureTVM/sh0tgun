#!/usr/bin/python
import socket
import sys
import subprocess
import logging

def main(args):
	if len(args) != 3:
		logging.error("Usage: smtprecon.py <ip address> <port>")
		return

	#SMTPSCAN = "nmap -vv -sV -Pn -p 25,465,587 --script=smtp-vuln* %s" % (ip)
	#results = subprocess.check_output(SMTPSCAN, shell=True)

	#f = open("results/smtpnmapresults.txt", "a")
	#f.write(results)
	#f.close
	
	ip = sys.argv[1]
	port = sys.argv[2]

	logging.info("Trying SMTP Enum on " + ip)
	names = open('/usr/share/metasploit-framework/data/wordlists/namelist.txt', 'r')
	for name in names:
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connect=s.connect((ip,25))
		banner=s.recv(1024)
		s.send('HELO test@test.org \r\n')
		result= s.recv(1024)
		s.send('VRFY ' + name.strip() + '\r\n')
		result=s.recv(1024)
		if ("not implemented" in result) or ("disallowed" in result):
			logging.error("VRFY Command not implemented on " + ip)
		if (("250" in result) or ("252" in result) and ("Cannot VRFY" not in result)):
			logging.warning("SMTP VRFY Account found on " + ip + ": " + name.strip()	)
			f = open(root+"findings.csv", "a+")
			f.write(ip+","+port+",SMTP,SMTP ACCOUNT: " + name.strip() + ",SMTP VRFY,\n")
			f.close()
		s.close()

if __name__=='__main__':
	main(sys.argv)