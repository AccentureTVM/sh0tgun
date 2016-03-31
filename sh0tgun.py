#!/usr/bin/env python
import sys
import subprocess
import pickle
import argparse
import re
import os
from os import listdir
from os.path import isfile, join
import math
import utility_scripts.nmapxmltocsv as nmapparser
import service_scripts.dirbust as dirbust
import service_scripts.dnsrecon as dnsrecon
import service_scripts.ftprecon as ftprecon
import service_scripts.smbrecon as smbrecon
import service_scripts.smtprecon as smtprecon
import service_scripts.snmprecon as snmprecon
import service_scripts.sshrecon as sshrecon
import service_scripts.medusa as medusa
import service_scripts.nse as nse
import time
import logging
import logging.handlers as handlers
import threading
import traceback
import sys
import glob
from multiprocessing import Pool, Queue

sep = os.path.sep
root = ""
targets = []
procs = 1
serviceDict = {}
enumCounter = {
	"http":0, 
	"ssl/http":0, 
	"https":0, 
	"ssh":0, 
	"snmp":0, 
	"smtp":0, 
	"domain":0, 
	"ftp":0, 
	"microsoft-ds":0, 
	"msrpc":0,
	"netbios-ssn":0,
	"ms-sql":0, 
	"ms-sql-s":0,
	"mysql":0,
	"drda":0,
	"ms-wbt-server":0,
	"rmiregistry":0,
	"total":0
}
pwCounter = {
	"total":0,
	"http":0,
	"ssl/http":0,
	"https":0,
	"ssh":0,
	"ftp":0,
	"ms-sql":0, 
	"ms-sql-s":0,
	"mysql":0,
	"vnc":0,
	"vnc-http":0
}
knownServices = {}
knownPwServices = {}
pool = None
lp = None
q = None
logger = None
rootlogger = None
FOUND_LEVEL_NUM = 35 

##########################################################
# Main functions
##########################################################	

def run(args):
	print ("***************************")
	print ("***	   SH0TGUN	  ***")
	print ("***			***")
	print ("***   Network Scanner   ***")
	print ("***  Service Enumerator ***")
	print ("***			***")
	print ("***   By Tucker Pettis  ***")
	print ("***************************")
	print ("")
	
	message = initialize(args)
	
	options = [
		"Manage Targets",
		"Run Nmap",
		"Enumerate Services",
		"Password Guess",
		"Show Findings"
	]
	menuChoice = ""
	while 1 == 1:
		menuChoice = executeMenu("",message,options)
		message = ""
		if menuChoice == 1:
			manageTargets()
		elif menuChoice == 2:
			if len(targets) == 0:
				message = "There are no targets to scan. Press 2 to add targets"
			else:
				runNmap()
		elif menuChoice == 3:
			enumServices()
			message = ""
		elif menuChoice == 4:
			pwGuess()
			message = ""
		elif menuChoice == 5:
			findings()
			message = ""
		elif menuChoice == 0:
			message = "This is the main menu!"
		else:
			message = "Enter a correct option"
	
def initialize(args):
	parser = argparse.ArgumentParser(description="Sh0tgun Network Scanning and Service Enumeration")
	parser.add_argument('-v', '--verbosity', help='Set verbosity as 1 (Silent), 2 (Normal), 3 (Verbose)')
	parser.add_argument('-p', '--processes', help='Set the maximum concurrent processes to spawn')
	parser.add_argument('-r', '--root', help='Set the project root directory')
	parser.add_argument('-t', '--test', action='store_true', help='For testing purposed')
	args = parser.parse_args()

	verbArg = args.verbosity
	procArg = args.processes
	rootArg = args.root
	testArg = args.test
	
	global root
	if rootArg != None:
		r = rootArg
	else:
		r = "/THIS/IS/NOT/A/DIRECTORY!!!!/"
	while not os.path.exists(r):
		v = "n"
		while v!="y":
			r = input("Enter valid project root folder: ")
			print (r)
			v = input("Is this correct? (Y/N): ")
			if len(v) != 0:
				v = v[0].lower()
	if r[-1] != "/":
		r = r+"/"
	root = r
	message = "Project root set to: " + root
	initDirs(testArg)
	message += "\nProject root directories successfully created\n"
	if os.path.isfile(root+"serviceDict.dat"):
		v = input("Previous NMAP Data was found here.  Would you like to load? If not, all previous data will be erased upon directory initialization. (Y/N): ")
		if len(v) != 0:
			v = v[0].lower()
		if v == "y":
			with open(root+"serviceDict.dat","rb") as f:
				global serviceDict
				serviceDict = pickle.load(f)
	
	if not os.path.isfile(root + "findings.csv"):
		fi = open(root + "findings.csv", 'w+')
		fi.write("ip,port,service,finding,tool,notes\n")
		fi.close()
	if not os.path.isfile(root + "password/passwords.csv"):
		fi = open(root + "password/passwords.csv", 'w+')
		fi.write("ip,port,username,password,service\n")
		fi.close()
	
	message += loggingInit(verbArg)
	
	global procs
	p = num(procArg)
	if p == None:
		p = -1
	while p < 1:
		p = input("Enter the MAXIMUM number of conncurrent processes to run (standard is 4): ")
		p = num(p)
		if p is None:
			p= -1
	procs = p
	global pool
	pool = Pool(processes=procs)
	message += "\nProcesses set to " + str(procs)
	
	v = ""
	while v!="y" and v!="n":
		v = input("Do you want to run Responder.py? (Y/N): ")
		if len(v) != 0:
			v = v[0].lower()
	if v == "y":
		responder()
		
	global knownServices
	knownServices = {
		"ssh":sshEnum, 
		"snmp":snmpEnum, 
		"smtp":smtpEnum, 
		"domain":dnsEnum, 
		"ftp":ftpEnum,  
		"netbios-ssn":smbEnum,
		"microsoft-ds":smbEnum,
		"ms-sql":mssqlEnum, 
		"ms-sql-s":mssqlEnum,
		"mysql":mysqlEnum,
		"drda":drdaEnum,
		"ms-wbt-server":rdpEnum,
		"http":httpEnum, 
		"ssl/http":httpEnum, 
		"https":httpEnum,
		"rmiregistry":rmiEnum
	}

	global knownPwServices
	knownPwServices = {
		"http":httpPW, 
		"ssl/http":httpPW, 
		"https":httpPW, 
		"ssh":sshPW, 
		"ftp":ftpPW, 
		"ms-sql":mssqlPW, 
		"ms-sql-s":mssqlPW,
		"mysql":mysqlPW,
		"vnc":vncPW,
		"vnc-http":vncPW
	}
		
	return (message)
	
def manageTargets():
	options = [
		"Import Targets from file",
		"Add targets manually",
		"Remove targets",
		"Show targets",
		"Remove all targets"
	]
	menuChoice = ""
	message = ""
	global targets
	while menuChoice != 0:
		menuChoice = executeMenu("",message,options)
		if menuChoice == 1:
			targetfile = ""
			while not os.path.isfile(targetfile):
				print ("Enter the path and file.  Please format the text file with 1 ip per line, no commas or end characters. ")
				targetfile = input(">>")
			f = open(targetfile, 'r')
			count = 0
			failed = []
			for ip in f:
				if re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$', ip.strip()) or re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip.strip()):
					print (ip.strip())
					targets.append(ip.strip())
					count += 1
				else:
					failed.append(ip)
			targets = list(set(targets))
			print ("loading...")
			time.sleep(2)
			f.close
			message = str(count) + " IP(s) successfully loaded."
			if len(failed) > 0:
				message = message + " The following are not valid IPs: " + str(failed)
		elif menuChoice == 2:
			addedTargets = input("Enter a list of comma separated targets: ")
			addedTargets = addedTargets.split(',')
			count = 0
			for ip in addedTargets:
				if not re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$', ip.strip()) and not re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip.strip()):
					count += 1
			if count > 0:
				message = "Error please enter valid IPs"
			else:
				targets = targets + addedTargets
				targets = list(set(targets))
				message = str(len(addedTargets)) + " IP(s) successfully loaded."
		elif menuChoice == 3:
			count = 0
			for ip in targets:
				print (str(count) + ") " + ip)
				count += 1
			remove = -2
			while remove < -1 or remove >= len(targets):
				remove = int(input ("Select the number to remove or -1 to cancel: "))
			if remove >= 0:
				ip = targets.pop(int(remove))
				message = "IP removed: " + ip
		elif menuChoice == 4:
			count = 0
			for ip in targets:
				print (ip)
			input("Press ENTER when done")
		elif menuChoice == 5:
			temp = ""
			while temp!="y" and temp!="n":
				temp = input("Are you sure you want to remove all targets? (Y/N): ")
				if len(temp) != 0:
					temp = temp[0].lower() 
			
			if temp == "y":
				targets = []
				message = "All targets removed"
			else:
				message = ""
		else:
			message = "Enter a correct option"
			
def runNmap():
	nmapOptions = {
		"timing" : 4,
		"verbosity" : "vvv",
		"port" : "Moderate",
		"versioning" : "V",
		"online" : "-Pn",
		"TCP" : "S",
		"OS" : "-O",
		"custom" : "",
		"Pn" : "-Pn",
		"Open" : "--open"
	}
	
	title = "nmap -" + nmapOptions["verbosity"] + " -T " + str(nmapOptions["timing"]) + " -p " + nmapOptions["port"] + " -s" + nmapOptions["TCP"] + nmapOptions["versioning"] + " " + nmapOptions["Pn"] + " " + nmapOptions["Open"] + " " + nmapOptions["OS"] + " " + nmapOptions["custom"] + " -oA " + root + "discovery/nmap/tcp ip"
	options = [
		"Set NMAP options",
		"Run TCP NMAP SCAN",
		"Run UDP NMAP Scan",
	]
	message = ""
	menuChoice = ""
	global serviceDict
	while menuChoice != 0:
		menuChoice = executeMenu(title,message,options)
		if menuChoice == 1:
			nmapOptions = setNmapOptions(nmapOptions)
		elif menuChoice == 2:
			logger.info("You are about to run an NMAP scan.  You cannot close this window until it is finished.")
			time.sleep(.5)
			v = ""
			while v!="y" and v!="n":
				v = input("Do you want to continue? (Y/N): ")
				if len(v) != 0:
					v = v[0].lower()
			if v == "y":
				jobs = [pool.apply_async(nmapScan, args=(ip,nmapOptions["timing"],nmapOptions["verbosity"],nmapOptions["port"],nmapOptions["versioning"],nmapOptions["online"],nmapOptions["TCP"],nmapOptions["OS"],nmapOptions["custom"],nmapOptions["Pn"],nmapOptions["Open"],"TCP"), error_callback=errorHandler) for ip in targets]
				for p in jobs:
					temp = p.get()
					for key in temp:
						if key in serviceDict:
							serviceDict[key] = serviceDict[key]+ temp[key]
						else:
							serviceDict[key] = temp[key]
				
				csvs = glob.glob(root + "discovery"+sep+"nmap"+sep+"tcp/tcp_*.csv")
				with open(root + "discovery"+sep+"nmap"+sep+"tcp_nmap_all.csv", "wb") as outfile:
					outfile.write(bytes('ip,hostname,port,protocol,service,version\n','utf-8'))
					for f in csvs:
						with open(f, "rb") as infile:
							outfile.write(infile.read())
			
				if os.path.isfile(root+"serviceDict.dat"):
					os.system("rm " + root + "serviceDict.dat")
				with open(root+"serviceDict.dat","wb") as f:
					pickle.dump(serviceDict, f)

				logger.info("NMAP Scans complete for all ips.  inidividual results in " + root + "discovery/nmap full results in " + root + "discovery/nmap/tcp_nmap_all.csv")
				time.sleep(.5)
				v = ""
				while v!="y" and v!="n":
					v = input("Would you like to open the results file? (Y/N): ")
					if len(v) != 0:
						v = v[0].lower()
				if v == "y":
					CMD = "gnome-terminal -x /usr/bin/leafpad " + root + "discovery/nmap/tcp_nmap_all.csv"
					subprocess.check_output(CMD.split(" "), stderr=subprocess.STDOUT)
				logger.info("Log data available at " + root + "reconscan.log")
				time.sleep(.5)
				input("Press Enter to continue.")
		
		elif menuChoice == 3:
			logger.info("You are about to run an NMAP scan.  You cannot close this window until it is finished.")
			time.sleep(.5)
			v = ""
			while v!="y" and v!="n":
				v = input("Do you want to continue? (Y/N): ")
				if len(v) != 0:
					v = v[0].lower()
			if v == "y":
				jobs = [pool.apply_async(nmapScan, args=(ip,nmapOptions["timing"],nmapOptions["verbosity"],nmapOptions["port"],nmapOptions["versioning"],nmapOptions["online"],nmapOptions["TCP"],nmapOptions["OS"],nmapOptions["custom"],nmapOptions["Pn"],nmapOptions["Open"],"TCP"), error_callback=errorHandler) for ip in targets]
				for p in jobs:
					temp = p.get()
					for key in temp:
						if key in serviceDict:
							serviceDict[key] = serviceDict[key]+ temp[key]
						else:
							serviceDict[key] = temp[key]
				
				csvs = glob.glob(root + "discovery"+sep+"nmap"+sep+"udp/udp*.csv")
				with open(root + "discovery"+sep+"nmap"+sep+"udp_nmap_all.csv", "wb") as outfile:
					outfile.write(bytes('ip,hostname,port,protocol,service,version\n','utf-8'))
					for f in csvs:
						with open(f, "rb") as infile:
							outfile.write(infile.read())
							
				if os.path.isfile(root+"serviceDict.dat"):
					os.system("rm " + root + "serviceDict.dat")
				with open(root+"serviceDict.dat","wb") as f:
					pickle.dump(serviceDict, f)

				logger.info("NMAP Scans complete for all ips.  inidividual results in " + root + "discovery/nmap full results in " + root + "discovery/nmap/udp_nmap_all.csv")
				time.sleep(1)
				while v!="y" and v!="n":
					v = input("Would you like to open the results file? (Y/N): ")
					if len(v) != 0:
						v = v[0].lower()
				if v == "y":
					CMD = "gnome-terminal -x /usr/bin/leafpad " + root + "discovery/nmap/udp_nmap_all.csv"
					subprocess.check_output(CMD.split(" "), stderr=subprocess.STDOUT)
				logger.info("Log data available at " + root + "reconscan.log")
				time.sleep(1)
				input("Press Enter to continue.")
		
		else:
			message = "Enter a correct option"
		
def enumServices():		
	
	options = [
		"Show All discovered Services",
		"Enumerate specific service",
		"Enumerate All Services",
	]
	message = ""
	menuChoice = ""
	while menuChoice != 0:
		menuChoice = executeMenu("",message,options)
		if menuChoice == 1:
			for serv in serviceDict:
				if serv in knownServices:
					print ("**"+serv)
				else:
					print (serv)
			print ("\n** indicates enumerable services")
			input ("\nPress Enter to return...")
			message = ""
		elif menuChoice == 2:
			choice = ""
			if serviceDict == {}:
				message = "No services detected: Please run NMAP scans first"
			else:
				count = 0
				for serv in knownServices:
					if serv in serviceDict:
						count += 1
				if count == 0:
					message = "No discovered services are enumerable.  Press 1 to see discovered services"
				else:
					while choice not in knownServices:
						for serv in knownServices:
							if serv in serviceDict:
								print (serv)
						choice = input('>>')
					logger.info("Starting enumeration for " + choice)
					global enumCounter
					for serv in serviceDict[choice]:
						enumCounter[choice] += 1
						enumCounter["total"] += 1
						pool.apply_async(knownServices[choice], args=(serv[0], serv[1], choice), callback=enumCallback, error_callback=errorHandler)
						
					input("Press ENTER to return to the menu.  Note: messages from background process may still be printed\n\n")
	
		elif menuChoice == 3:
			if serviceDict == {}:
				message = "No services detected: Please run NMAP scans first"
			else:
				logger.info("No enum tool for the following services: ")
				for serv in serviceDict:
					if serv not in knownServices:
						for ips in serviceDict[serv]:
							temp = ips[0]+":"+ips[1]+" "
						logger.info(" -"+serv+": "+ temp)
			
				logger.info("Starting Enumeration")
				jobs = []
				for services in knownServices:
					if services in serviceDict:
						for serv in serviceDict[services]:
							jobs.append(pool.apply_async(knownServices[services], args=(serv[0], serv[1], services), error_callback=errorHandler))
				
				for job in jobs:
					job.wait()
				logger.info("Enumeration has completed. See " + root + "discovery/ for details")
				input("\nPress Enter to continue.  Log data available at " + root + "reconscan.log")
	
		else:
			message = "Enter a correct option"
	
def pwGuess():
	medusaFlags = {
		"users":"-U wordlists/test.txt",
		"pws": "-P wordlists/test.txt",
		"jb": "-e ns",
		"verbosity": "-v6",
		"combo" : "",
		"ssl" : "",
		"custom" : ""
	}
	medusaOptions = [
		"Set user wordlist",
		"Set pw wordlist",
		"Set combo file",
		"Set blanks and joes",
		"Enable SSL",
		"Set verbosity",
		"Custom flags"
	]
	options = [
		"Change medusa settings",
		"PW guess specific service",
		"PW guess All"
	]
	
	message = ""	
	menuChoice = ""
	while menuChoice != 0:
		title = "medusa -h ip_address -n port " + medusaFlags["users"] + " " + medusaFlags["pws"] + " " + medusaFlags["jb"] + " " + medusaFlags["verbosity"] + " " + medusaFlags["combo"] + " " + medusaFlags["ssl"] + " " + medusaFlags["custom"] + " -M module"
		menuChoice = executeMenu(title,message,options)
		if menuChoice == 1:
			message2 = ""	
			menuChoice2 = ""
			while menuChoice2 != 0:
				title = "medusa -h ip_address -n port " + medusaFlags["users"] + " " + medusaFlags["pws"] + " " + medusaFlags["jb"] + " " + medusaFlags["verbosity"] + " " + medusaFlags["combo"] + " " + medusaFlags["ssl"] + " " + medusaFlags["custom"] + " -M module"
				menuChoice2 = executeMenu(title,message2,medusaOptions)
				if menuChoice2 == 1:
					r = "/THIS/IS/NOT/A/DIRECTORY!!!!/"
					while not os.path.isfile(r):
						v = "n"
						while v!="y":
							r = input("Enter the full path to the wordlist: ")
							print (r)
							v = input("Is this correct? (Y/N): ")
							if len(v) != 0:
								v = v[0].lower()	
					medusaFlags["users"] = "-U " + r	
				elif menuChoice2 == 2:
					r = "/THIS/IS/NOT/A/DIRECTORY!!!!/"
					while not os.path.isfile(r):
						v = "n"
						while v!="y":
							r = input("Enter the full path to the wordlist: ")
							print (r)
							v = input("Is this correct? (Y/N): ")
							if len(v) != 0:
								v = v[0].lower()	
					medusaFlags["pws"] = "-P " + r	
				elif menuChoice2 == 3:
					r = "/THIS/IS/NOT/A/DIRECTORY!!!!/"
					while not os.path.isfile(r):
						v = "n"
						while v!="y":
							r = input("Enter the full path to the wordlist: ")
							print (r)
							v = input("Is this correct? (Y/N): ")
							if len(v) != 0:
								v = v[0].lower()	
					medusaFlags["combo"] = "-C " + r	
				elif menuChoice2 == 4:
					jb = "a"
					while jb != "" and jb != "ns" and jb != "n" and jb != "s":
						jb = input("Do you want to test blanks and/or joes? (Enter \"n\", \"s\", \"ns\" or press ENTER for neither): ")
					if jb == "":
						medusaFlags["jb"] = ""
					else:
						medusaFlags["jb"] = "-e " + jb
				elif menuChoice2 == 5:
					v = ""
					while v!="y" and v!="n":
						v = input("Do you want to enable SSL? (Y/N): ")
						if len(v) != 0:
							v = v[0].lower()
					if v == "y":
						medusaFlags["ssl"] = "-s"
					else:
						medusaFlags["ssl"] = ""
				elif menuChoice2 == 6:
					v = -1
					while v == -1:
						v = input("Enter verbosity 1-6: ")
						v = num(v)
						if v == None:
							v = -1
						elif v < 1 or v > 6:
							v = -1
						else:
							medusaFlags["verbosity"] = "-v" + str(v)
				elif menuChoice2 == 7:
					v = "n"
					while v != "y":
						custom = input("Enter custom options: ")
						print (custom)
						v = input("Is this correct? (Y/N): ")
						if len(v) != 0:
							v = v[0].lower()
					medusaFlags["custom"] = custom
				else:
					message2 = "Enter a correct option"
		elif menuChoice == 2:
			choice = ""
			if serviceDict == {}:
				message = "No services detected: Please run NMAP scans first"
			else:
				count = 0
				for serv in knownPwServices:
					if serv in serviceDict:
						count += 1
				if count == 0:
					message = "No discovered services are guessable."
				else:
					print("Type the full name of the service you would like to guess or press 0 to go back")
					while choice not in knownPwServices and choice != "0":
						for serv in knownPwServices:
							if serv in serviceDict:
								print (serv)
						choice = input('>>')
					if choice != "0":
						logger.info("Starting pw guess for " + choice)
						for serv in serviceDict[choice]:
							pwCounter[choice] += 1
							pwCounter["total"] += 1
							pool.apply_async(knownPwServices[choice], args=(serv[0], serv[1], choice, medusaFlags), callback = pwCallback, error_callback=errorHandler)
					
					input("Press ENTER to go back to the main menu\n\n")

		elif menuChoice == 3:
			if serviceDict == {}:
				message = "No services detected: Please run NMAP scans first"
			else:
				logger.info("No PW guess tool for the following services: ")
				for serv in serviceDict:
					if serv not in knownPwServices:
						for ips in serviceDict[serv]:
							temp = ips[0]+":"+ips[1]+" "
						logger.info(" -"+serv+": "+ temp)
			
				logger.info("Starting Guessing on all possible services")
				jobs = []
				for services in knownPwServices:
					if services in serviceDict:
						for serv in serviceDict[services]:
							jobs.append(pool.apply_async(knownPwServices[services], args=(serv[0], serv[1], services, medusaFlags), callback = pwCallback, error_callback=errorHandler))
							
				for job in jobs:
					job.wait()
				
				logger.info("Guessing has completed. See " + root + "password/ for details")
				logger.info("Log data available at " + root + "reconscan.log")
				input("\nPress Enter to continue.")
		else:
			message = "Enter a correct option"

def responder():
	options = [
		"Run Responder",
		"Set flags",
		"Set interface",
		"Set responder location"
	]
	flags = "vbwFr"
	interface = "eth0"
	loc = "/usr/share/responder/Responder.py"
	
	message = ""
	menuChoice = ""
	title = ""
	while menuChoice != 0:
		t1 = ""
		t2 = ""
		t3 = ""
		if interface != "":
			t1 = "-I " + interface
		if flags != "":
			t3 = "-" + flags
		title = "python " + loc + " " + t3 + " " + t1
		menuChoice = executeMenu(title,message,options)
		if menuChoice == 1:
			if interface != "":
				RESPONDER = "gnome-terminal -x " + title
				logger.info("Running Responder")
				subprocess.check_output(RESPONDER.split(" "), stderr=subprocess.STDOUT)
				break
		elif menuChoice == 2:
			f = "-"
			while f != "":
				f = input("Enter the desired option flags (no -): ")
				ft = f.replace("A", "")
				ft = ft.replace("b", "")
				ft = ft.replace("r", "")
				ft = ft.replace("d", "")
				ft = ft.replace("F", "")
				ft = ft.replace("w", "")
				ft = ft.replace("f", "")
				ft = ft.replace("v", "")
				if ft != "":
					message = "Not a valid set of flags (NB: -u and --lm are not available\n)"
				else:
					flags = f
					f = ""							
		elif menuChoice == 3:
			v = "n"
			while v!="y":
				temp = input("Enter the interface: ")
				print (temp)
				v = input("Is this correct? (Y/N): ")
				if len(v) != 0:
					v = v[0].lower()
			interface = temp
		elif menuChoice == 5:
			r = "/THIS/IS/NOT/A/DIRECTORY!!!!/"
			while checkResponder(r) == False:
				v = "n"
				while v!="y":
					r = input("Enter the full path to Responder.py: ")
					print (r)
					v = input("Is this correct? (Y/N): ")
					if len(v) != 0:
						v = v[0].lower()		
			loc = r
		else:
			message = "Enter a correct option"	

def findings():
	options = [
		"Open findings file",
		"Display All Findings",
		"Display findings by IP",
		"Open passwords file",
		"Display all credentials",
		"Display credentials by IP or service"
	]
	title = ""
	message = ""
	menuChoice = ""
	while menuChoice != 0:
		menuChoice = executeMenu(title,message,options)
		if menuChoice == 1:
			CMD = "gnome-terminal -x /usr/bin/leafpad "+ root + "findings.csv"
			logger.info("Opening " + root + "findings.csv")
			subprocess.check_output(CMD.split(" "))
			message = "Findings opened with leafpad"
		elif menuChoice == 2:
			count = 1
			logger.info("Showing all findings")
			time.sleep(.2)
			with open(root + "findings.csv", "r") as fi:
				lines = fi.readlines()
				if len(lines) > 0:
					for line in lines:
						if count != 1:
							line = line.split(",")
							print (line[3] + " found on " + line[0] + ":"  + line[1])
							if count % 10 == 0:
								input ("Press any button to continue")
						count = count + 1
				else:
					logger.info("No findings found")
					time.sleep(.2)
			input("Press ENTER to continue...")
			message = ""
		elif menuChoice == 3:
			count = 1
			ip = "123"
			flag = 0
			while not re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip.strip()):
				ip = input("Enter a valid ip address: ")
			
			logger.info("Showing findings for " + ip)
			time.sleep(.2)
			with open(root + "findings.csv", "r") as fi:
				lines = fi.readlines()
				if len(lines) > 0:
					for line in lines:
						line = line.split(",")
						if line[0] == ip:
							print (line[3] + " found on " + line[0] + ":" + line[1])
							if count % 10 == 0:
								input ("Press any button to continue")
							count = count + 1
					if count == 1:
						logger.info("No findings for " + ip)
						time.sleep(.2)
				else:
					logger.info("No findings found")
					time.sleep(.2)
			input("Press ENTER to continue...")
			message = ""
		elif menuChoice == 4:
			CMD = "gnome-terminal -x /usr/bin/leafpad "+ root + "password/passwords.csv"
			logger.info("Opening " + root + "password/passwords.csv")
			subprocess.check_output(CMD.split(" "))
			message = "Credentials opened with leafpad"
		elif menuChoice == 5:
			count = 1
			logger.info("Showing all credentials")
			time.sleep(.2)
			with open(root + "password/passwords.csv", "r") as fi:
				lines = fi.readlines()
				if len(lines) > 0:
					for line in lines:
						if count != 1:
							line = line.split(",")
							print (line[2] + "/" + line[3] + " for " + line[4].rstrip() + " on " + line[0] + ":"  + line[1])
							if count % 10 == 0:
								input ("Press any button to continue")
						count = count + 1
				else:
					logger.info("No findings found")
					time.sleep(.2)
			input("Press ENTER to continue...")
			message = ""
		elif menuChoice == 6:
			count = 1
			ip = "123"
			flag = 0
			while ip not in knownPwServices and not re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip.strip()):
				ip = input("Enter a valid ip address or service: ")
			
			logger.info("Showing findings for " + ip)
			time.sleep(.2)
			with open(root + "password/passwords.csv", "r") as fi:
				lines = fi.readlines()
				if len(lines) > 0:
					for line in lines:
						line = line.split(",")
						if line[0] == ip or line[4].rstrip() == ip:
							print (line[2] + "/" + line[3] + " for " + line[4].rstrip() + " on " + line[0] + ":"  + line[1])
							if count % 10 == 0:
								input ("Press any button to continue")
							count = count + 1
					if count == 1:
						logger.info("No credentials for " + ip)
						time.sleep(.2)
				else:
					logger.info("No credentials found")
					time.sleep(.2)
			input("Press ENTER to continue...")
			message = ""
		else:
			message = "Enter a correct option"

##########################################################
# NMAP functions
##########################################################
	
def setNmapOptions(nmapOptions):
	menuChoice2 = -1
	message2 = ""
	while (menuChoice2 != 0):
		print(chr(27) + "[2J")
		print (message2 + "\n")
		print ("nmap -" + nmapOptions["verbosity"] + " -T " + str(nmapOptions["timing"]) + " -p " + nmapOptions["port"] + " -s" + nmapOptions["TCP"] + nmapOptions["versioning"] + " " + nmapOptions["Pn"] + " " + nmapOptions["Open"] + " " + nmapOptions["OS"] + nmapOptions["custom"] + " -oA " + root + "discovery/nmap/tcp ip")
		print ("1) Set Timing -- Current: " + str(nmapOptions["timing"]))
		print ("2) Set Ports -- Current: " + nmapOptions["port"])
		print ("3) Set verbosity -- Current: " + nmapOptions["verbosity"])
		print ("4) Set TCP Scan Type -- Current: s" + nmapOptions["TCP"])
		print ("5) Set Service Versioning -- Current: " + nmapOptions["versioning"])
		print ("6) Set OS detection -- Current: " + nmapOptions["OS"])
		print ("7) Treat all hosts online -- Current: " + nmapOptions["Pn"])
		print ("8) Only show open ports -- Current: " + nmapOptions["Open"])
		print ("9) Custom flag")
		print ("\n0) Done")
		menuChoice2 = input('Option: ')
		message2 = ""
		menuChoice2 = num(menuChoice2)
		if menuChoice2 is None:
			menuChoice2 = -1
			message2 = "Enter a valid option"
		elif menuChoice2 == 1:
			timing = 0
			while timing < 1 or timing > 5 or math.isnan(timing):
				timing = int(input("Enter a number 1 - 5 (Slowest to Fastest, default is 4): "))
			nmapOptions["timing"] = timing
		elif menuChoice2 == 2:
			print ("1) Full = 0-65535")
			print ("2) Moderate = Top 1000 ports")
			print ("3) light = Top 125 ports")
			p=0
			while math.isnan(p) or p < 1 or p >= 4:
				p = int(input("Enter the number of the scan intensity (1-3)"))
				if p == 1:
					nmapOptions["port"] = "Full"
				elif p == 2:
					nmapOptions["port"] = "Moderate"
				elif p == 3:
					nmapOptions["port"] = "Light"
				elif p == 4:
				    temp = input("Enter the desired ports")
				    print temp
				    v = input("Is this correct? NB if not formatted correctly, future errors will occur")
				    if len(v) != 0:
				        v = v[0].lower
				    if v == "y"
				        nmapOptions["port"] = temp
				else:
					print ("not valid")
		elif menuChoice2 == 3:
			verbosity = ""
			while verbosity != "v" and verbosity != "vv" and verbosity != "vvv":
				verbosity = input("Enter verbosity level (v, vv, or vvv): ")
				verbosity = verbosity.lower()
			nmapOptions["verbosity"] = verbosity
		elif menuChoice2 == 4:
			TCP= ""
			while TCP!= "S" and TCP!= "T" and TCP!= "A" and TCP!= "W" and TCP!= "M":
				TCP= input("Enter the tcp scan type (S, T, A, W, or M): ")
				TCP= TCP.upper()
			nmapOptions["TCP"] = TCP
		elif menuChoice2 == 5:
			v = input("Do you want to run service versioning? (Y/N): ")
			if len(v) != 0:
				v = v[0].lower()
			if v == "y":
				nmapOptions["versioning"] = "V"
			else:
				nmapOptions["versioning"] = ""
		elif menuChoice2 == 6:
			v = input("Do you want to run  OS detection? (Y/N): ")
			if len(v) != 0:
				v = v[0].lower()
			if v == "y":
				nmapOptions["OS"] = "-O"
			else:
				nmapOptions["OS"] = ""
		elif menuChoice2 == 7:
			v = input("Do you want to treat all hosts as online? (Y/N): ")
			if len(v) != 0:
				v = v[0].lower()
			if v == "y":
				nmapOptions["Pn"] = "-Pn"
			else:
				nmapOptions["Pn"] = ""
		elif menuChoice2 == 8:
			v = input("Do you want to only show open ports? (Y/N): ")
			if len(v) != 0:
				v = v[0].lower()
			if v == "y":
				nmapOptions["Open"] = "--open"
			else:
				nmapOptions["Open"] = ""
		elif menuChoice2 == 9:
			nmapOptions["custom"] = input("Enter custom flags, space delimited: ")
		elif menuChoice2 != 0:
			message2 = "Enter a correct option"
	return nmapOptions
			
def nmapScan(ip_address,timing,verbosity,port,versioning,online,TCP,OS,custom,Pn,Open,type):
	if port == "Light":
		ports = " --top-ports 125"
	elif port == "Moderate":
		ports = " --top-ports 1000"
	elif port == "Full":
		ports = " -p 0-65535"
	else ports = port

	ip_address = ip_address.strip()
	ip_format = ip_address.replace("/", "_")
	TCPSCAN = "nmap -" + verbosity + " -T " + str(timing) + ports + " -s" + TCP + versioning + " " + Pn + " " + Open + " " + OS + custom +" -oA " + root + "discovery/nmap/tcp/tcp_%s %s"  % (ip_format, ip_address)
	UDPSCAN = "nmap -" + verbosity + " -T " + str(timing) + ports + " -s" + TCP + versioning + " " + Pn + " " + Open + " " + OS + custom +" -oA " + root + "discovery/nmap/tcp/udp_%s %s"  % (ip_format, ip_address)
	tempDict = {}

	if type == "TCP":
		logger.info("Running TCP nmap scans for " + ip_address)
		try:
			subprocess.check_output(TCPSCAN.split(' '), stderr=subprocess.STDOUT)
			try:
				fo = open(root + "discovery"+sep+"nmap"+sep+"tcp/tcp_"+ip_format+".csv", 'w+')
				tempDict = nmapparser.process(root+"discovery"+sep+"nmap"+sep+"tcp/tcp_"+ip_format+".xml", fo)
				fo.close()
			except:
				logger.error ("Error Processing NMAP Results.  Nmap scans still available at /discover/nmap/tcp")
		except:
			logger.error("Error running NMAP scans")
		
		
	if type == "UDP":
		logger.info("Running UDP nmap scans for " + ip_address)
		try:
			subprocess.check_output(UDPSCAN.split(' '), stderr=subprocess.STDOUT)
			try:
				fo = open(root + "discovery"+sep+"nmap"+sep+"udp/udp_"+ip_format+".csv", 'w+')
				fo.close()
				tempDict = nmapparser.process(root+"discovery"+sep+"nmap"+sep+"udp/udp_"+ip_format+".xml", fo)
			except:
				logger.error ("Error Processing NMAP Results.  Nmap scans still available at /discover/nmap/tcp")
		except:
			logger.error("Error running NMAP scans")

	logger.info(type + " Nmap scans completed for " + ip_address)
	return tempDict		
				
##########################################################
# Enum functions
##########################################################

def drdaEnum(ip_address, port, service):
	logger.info("Detected DRDA on " + ip_address + ":" + port)
	logger.info("Performing nmap DRDA script scan for " + ip_address + ":" + port)
	DRDASCAN = nse.DRDA(ip_address, port)	
	try:
		nseout = subprocess.check_output(DRDASCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/drda/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("Unknown: NSE failed for DRDA " + ip_address + ":"+ port)
	return [service, ip_address, port]
	
def rdpEnum(ip_address, port, service):
	logger.info("Detected RDP on " + ip_address + ":" + port)
	logger.info("Performing nmap RDP script scan for " + ip_address + ":" + port)
	RDPSCAN = nse.Remote_Desktop(ip_address, port)	
	try:
		nseout = subprocess.check_output(RDPSCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/rdp/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for RDP " + ip_address + ":"+ port)
	return [service, ip_address, port]
	
def rmiEnum(ip_address, port, service):
	logger.info("Detected JAVA RMI on " + ip_address + ":" + port)
	logger.info("Performing nmap RMI script scan for " + ip_address + ":" + port)
	RMISCAN = nse.RMI_Registry(ip_address, port)	
	try:
		nseout = subprocess.check_output(RMISCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/rmi/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for DRDA " + ip_address + ":"+ port)
	return [service, ip_address, port]

def dnsEnum(ip_address, port, service):
	logger.info("Detected DNS on " + ip_address + ":" + port)
	if port.strip() == "53":
		dnsrecon.main(["",ip_address, root])
	else:
		logger.error("Can only run dns enum on port 53")
	
	logger.info("Performing nmap DNS script scan for " + ip_address + ":" + port)
	DNSSCAN = nse.DNS(ip_address, port)	
	try:
		nseout = subprocess.check_output(DNSSCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/dns/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for snmp " + ip_address + ":"+ port)
	return [service, ip_address, port]

def httpEnum(ip_address, port, service):
	logger.info("Detected http on " + ip_address + ":" + port)
	logger.info("Performing nmap web script scan for " + ip_address + ":" + port + " see directory/http for results")
	HTTPSCAN = nse.http(ip_address, port)
	try:
		nseout = subprocess.check_output(HTTPSCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/http/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for http " + ip_address + ":"+ port)

	logger.info("Using Dirbuster for " + ip_address + ":" + port + " see directory/http for results")
	dirbust.main(["",ip_address,port,False])

	logger.info("Performing NIKTO scan for " + ip_address + ":" + port + " see directory/http for results")
	NIKTOSCAN = "nikto -host %s -p %s" % (ip_address, port)
	try:
		NIKTOSCAN = subprocess.check_output(NIKTOSCAN.split(' '))
		NIKTOSCAN = NIKTOSCAN.decode('utf-8')
		out = root + "discovery/http/" + ip_address + "NIKTO.txt"
		niktoout = open(out, "w+")
		niktoout.write(NIKTOSCAN)
		niktoout.close()
	except:
		logger.error("NIKTO failed for " + ip + ":"+ port)
	return  [service, ip_address, port]

def mssqlEnum(ip_address, port, service):
	logger.info("Detected MS-SQL on " + ip_address + ":" + port)
	logger.info("Performing nmap mssql script scan for " + ip_address + ":" + port)
	MSSQLSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,mssql.username-sa,mssql.password-sa -oX %sdiscovery/mssql/%s_mssql.xml %s" % (port, root, ip_address, ip_address)
	try:
		nseout = subprocess.check_output(MSSQLSCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/mssql/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for mssql" + ip_address + ":"+ port)

	return [service, ip_address, port]

def mysqlEnum(ip_address, port, service):
	logger.info("Detected mySQL on " + ip_address + ":" + port)
	logger.info("Performing nmap mysql script scan for " + ip_address + ":" + port)
	# mysql-vuln-cve2012-2122
	MYSQLSCAN = "nmap -vv -sV -Pn -p %s --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables -oX %sdiscovery/mysql/%s_mysql.xml %s" % (port, root, ip_address, ip_address)
	try:
		nseout = subprocess.check_output(MYSQLSCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/mysql/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for mysql" + ip_address + ":"+ port)


	return [service, ip_address, port]

def sshEnum(ip_address, port, service):
	logger.info("Detected SSH on " + ip_address + ":" + port)
	# sshrecon.main(["", ip_address, port])				 NOTHING HERE YET
	logger.info("Performing nmap SSH script scan for " + ip_address + ":" + port)
	SSHSCAN = nse.SSH(ip_address, port)	
	try:
		nseout = subprocess.check_output(SSHSCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/ssh/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for ssh " + ip_address + ":"+ port)
	return [service, ip_address, port]

def snmpEnum(ip_address, port, service):
	logger.info("Detected snmp on " + ip_address + ":" + port)
	snmprecon.main(["", ip_address, root])
	
	logger.info("Performing nmap snmp script scan for " + ip_address + ":" + port)
	SNMPSCAN = nse.SNMP(ip_address, port)	
	try:
		nseout = subprocess.check_output(SNMPSCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/snmp/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for snmp " + ip + ":"+ port)
		
	return [service, ip_address, port]

def smtpEnum(ip_address, port, service):
	logger.info("Detected smtp on " + ip_address + ":" + port)
	smtprecon.main(["", ip_address, port])
	
	logger.info("Performing nmap smtp script scan for " + ip_address + ":" + port)
	SMTPSCAN = nse.SMTP(ip_address, port)	
	try:
		nseout = subprocess.check_output(SMTPSCAN.split(' '))
		nseout = nseout.decode('utf-8')
		resultsfile = root + "discovery/smtp/" + ip_address + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logger.error("NSE failed for smtp " + ip_address + ":"+ port)
		
	return [service, ip_address, port]

def smbEnum(ip_address, port, service):
	logger.info("Detected SMB on " + ip_address + ":" + port)
	smbrecon.main(["",ip_address, port,root])
	return [service, ip_address, port]

def ftpEnum(ip_address, port, service):
	logger.info("Detected ftp on " + ip_address + ":" + port)
	ftprecon.main(["",ip_address,port,root])

	return [service, ip_address, port]
	
##########################################################
# PW Guess functions
##########################################################
		
def httpPW(ip, port, service, options):
	logger.info("Starting password guess for http web form at " + ip + ":" + port)
	medusa.webformCrack(ip, port, root, options)
	logger.info("Password guess for http at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]
	
def sshPW(ip, port, service, options):
	logger.info("Starting password guess for ssh  at " + ip + ":" + port)
	medusa.sshCrack(ip, port, root, options)
	logger.info("Password guess for ssh at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]
	
def ftpPW(ip, port, service, options):
	logger.info("Starting password guess for ftp at " + ip + ":" + port)
	medusa.ftpCrack(ip, port, root, options)
	logger.info("Password guess for ftp at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]

def mssqlPW(ip, port, service, options):
	logger.info("Starting password guess for MS SQL at " + ip + ":" + port)
	medusa.mssqlCrack(ip, port, root, options)
	logger.info("Password guess for mssql at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]

def mysqlPW(ip, port, service, options):
	logger.info("Starting password guess for MySQL at " + ip + ":" + port)
	medusa.mysqlCrack(ip, port, root, options)
	logger.info("Password guess for mysql at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]
	
def vncPW(ip, port, service, options):
	logger.info("Starting password guess for VNC at " + ip + ":" + port)
	medusa.vncCrack(ip, port, root, options)
	logger.info("Password guess for vnc at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]

##########################################################
# Utility functions
##########################################################

def errorHandler(e):
	traceback.print_exception(type(e), e, e.__traceback__)
	
def logger_thread(q):
	while True:
		record = q.get()
		if record is None:
			break
		rootlogger = logging.getLogger('sh0tgun_logger')
		rootlogger.handle(record)

def checkResponder(r):
	if os.path.isfile(r):
		if r[-12:] == "Responder.py":
			return True
		else:
			return False
	else:
		return False

def enumCallback(retVal):
	global enumCounter
	enumCounter[retVal[0] ] -= 1
	logger.info ("Enumeration of " + retVal[0] + " has completed for " +retVal[1] + ":" + retVal[2])
	if enumCounter[retVal[0] ] == 0:
		logger.info ("Enumeration of all " + retVal[0] + " instances has completed. See " + root + "discovery/ for details")
	if enumCounter["total"] == 0:
		logger.info ("Enumeration of all services has completed. See " + root + "discovery/ for details")
	
def pwCallback(retVal):
	global pwCounter
	pwCounter[retVal[0] ] -= 1
	logger.info ("Guessing of " + retVal[0] + " has completed for " +retVal[1] + ":" + retVal[2])
	if pwCounter[retVal[0] ] == 0:
		logger.info ("Guessing of all " + retVal[0] + " instances has completed. See " + root + "password/ for details")
	if pwCounter["total"] == 0:
		logger.info ("Guessing of all services has completed. See " + root + "password/ for details")
	
def num(s):
	try:
		return int(s)
	except:
		return None

def loggingInit(verbArg):
	global q
	q = Queue()
	global lp	
	
	l = num(verbArg)
	if l == None:
		lev = 30
		message = "Log level set to Findings and Errors\n\t\tNOTE: all events are logged to " + root + "sh0tgun.log"
	elif l < 2:
		lev = 50
		message = "Log level set to Critical\n\tNOTE: all events are logged to " + root + "sh0tgun.log"
	elif l == 2:
		lev = 30
		message = "Log level set to Findings and Errors\n\tNOTE: all events are logged to " + root + "sh0tgun.log"
	elif l > 2:
		lev = 5
		message = "Log level set to Verbose\n\tNOTE: all events are logged to " + root + "sh0tgun.log"
	
	logging.addLevelName(30, "FOUND")
	
	global logger
	global rootlogger
	rootlogger = logging.getLogger('sh0tgun_logger')
	rootlogger.setLevel(5)
	fh = logging.FileHandler(root+"sh0tgun.log")
	fh.setLevel(logging.DEBUG)
	
	ch = logging.StreamHandler()
	ch.setLevel(lev)
	
	formatter = logging.Formatter('%(levelname)s: %(message)s')
	fh.setFormatter(formatter)
	ch.setFormatter(formatter)
	
	rootlogger.addHandler(fh)
	rootlogger.addHandler(ch)
	
	qh = handlers.QueueHandler(q)
	qh.setLevel(logging.DEBUG)
	
	logger = logging.getLogger("qlogger")
	logger.setLevel(5)
	logger.addHandler(qh)
	
	lp = threading.Thread(target=logger_thread, args=(q,))
	lp.start()
	
	return message
		
def initDirs(test):
	if test:
		os.system("rm -r " + root + "discovery")
		os.system("rm -r " + root + "password")
		os.system("rm " + root + "findings.csv")
		os.system("rm " + root + "serviceDict.dat")
		os.system("rm " + root + "sh0tgun.log")
	checkandmk(root + 'issues')
	checkandmk(root + 'lists')
	checkandmk(root + 'password')
	checkandmk(root + 'pillage')
	checkandmk(root + 'discovery')
	checkandmk(root + 'discovery'+sep+'dirb')
	checkandmk(root + 'discovery'+sep+'dns')
	checkandmk(root + 'discovery'+sep+'ftp')
	checkandmk(root + 'discovery'+sep+'smb')
	checkandmk(root + 'discovery'+sep+'smtp')
	checkandmk(root + 'discovery'+sep+'snmp')
	checkandmk(root + 'discovery'+sep+'ssh')
	checkandmk(root + 'discovery'+sep+'mssql')
	checkandmk(root + 'discovery'+sep+'db2')
	checkandmk(root + 'discovery'+sep+'oracle')
	checkandmk(root + 'discovery'+sep+'nmap')
	checkandmk(root + 'discovery'+sep+'nmap'+sep+'tcp')
	checkandmk(root + 'discovery'+sep+'nmap'+sep+'udp')
	checkandmk(root + 'discovery'+sep+'http')
	checkandmk(root + 'discovery'+sep+'vnc')
	checkandmk(root + 'discovery'+sep+'mysql')
	checkandmk(root + 'discovery'+sep+'drda')
	checkandmk(root + 'discovery'+sep+'rdp')
	checkandmk(root + 'discovery'+sep+'rmi')
	checkandmk(root + 'password'+sep+'ftp')
	checkandmk(root + 'password'+sep+'smb')
	checkandmk(root + 'password'+sep+'smtp')
	checkandmk(root + 'password'+sep+'ssh')
	checkandmk(root + 'password'+sep+'mssql')
	checkandmk(root + 'password'+sep+'db2')
	checkandmk(root + 'password'+sep+'oracle')
	checkandmk(root + 'password'+sep+'http')
	checkandmk(root + 'password'+sep+'vnc')
	checkandmk(root + 'password'+sep+'mysql')
	checkandmk(root + 'password'+sep+'rdp')
	return

def checkandmk(path):
	if not os.path.exists(path):
		os.makedirs(path)

def executeMenu(title, message, options):
	menuChoice = ""
	while (menuChoice != "q"):
		print(chr(27) + "[2J")
		print (message + "\n")
		print ("-------------------------------")
		print (title + "\n")
		count = 1
		for opt in options:
			print (str(count) + ") " + opt)
			count = count + 1
		
		print ("\n0) Main Menu")
		print ("Q) Quit\n")
		menuChoice = input('Option #:')
		if menuChoice == '':
			message = "Enter a correct Option"
		elif menuChoice[0].lower() != "q":
			temp = num(menuChoice)
			if temp is not None:
				return temp
			else:
				menuChoice = ""
				message =  "Enter a correct option"
		else:
			menuChoice = ""
			choice = input ("Are you sure you want to quit? (Y/N): ")
			if len(choice) != 0:
				choice = choice[0].lower()
			if (choice == "y"):
				q.put(None)
				lp.join()
				sys.exit()

##########################################################
# Main function
##########################################################
if __name__=='__main__':
	if sys.version_info[0] != 3 or sys.version_info[1] < 1:
		print("\nEXIT: This script requires Python version 3.1 or higher\n")
		sys.exit(1)
	run(sys.argv)
