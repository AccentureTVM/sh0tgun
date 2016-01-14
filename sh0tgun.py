#!/usr/bin/env python
import sys
import subprocess
import pickle
import argparse
import re
import os
import math
import utilities.nmapxmltocsv as nmapparser
import scripts.dirbust as dirbust
import scripts.dnsrecon as dnsrecon
import scripts.ftprecon as ftprecon
import scripts.smbrecon as smbrecon
import scripts.smtprecon as smtprecon
import scripts.snmprecon as snmprecon
import scripts.sshrecon as sshrecon
import scripts.medusa as medusa
import scripts.nse as nse
import time
import logging
import threading
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
FOUND_LEVEL_NUM = 35 

##########################################################
# Main functions
##########################################################	

def run(args):
	print ("***************************")
	print ("***	   SH0TGUN	   ***")
	print ("***					 ***")
	print ("***   Network Scanner   ***")
	print ("***  Service Enumerator ***")
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
	args = parser.parse_args()

	verbArg = args.verbosity
	procArg = args.processes
	rootArg = args.root
	
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
	if os.path.isfile(root+"serviceDict.dat"):
		v = input("Previous NMAP Data was found here.  Would you like to load? If not, all previous data will be erased upon directory initialization (2). (Y/N): ")
		if len(v) != 0:
			v = v[0].lower()
		if v == "y":
			with open(root+"serviceDict.dat","rb") as f:
				global serviceDict
				serviceDict = pickle.load(f)
			f.close()
	message = "Project root set to: " + root
	initDirs()
	message += "\nProject root directories successfully created\n"
	
	if not os.path.isfile(root + "findings.csv"):
		fi = open(root + "findings.csv", 'w+')
		fi.write("ip,port,service,finding,tool,notes")
		fi.close()
	
	loggingInit(verbArg)
	
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
		"http":httpEnum, 
		"ssl/http":httpsEnum, 
		"https":httpsEnum, 
		"ssh":sshEnum, 
		"snmp":snmpEnum, 
		"smtp":smtpEnum, 
		"domain":dnsEnum, 
		"ftp":ftpEnum, 
		"microsoft-ds":smbEnum, 
		"msrpc":smbEnum,
		"netbios-ssn":smbEnum,
		"ms-sql":mssqlEnum, 
		"ms-sql-s":mssqlEnum,
		"mysql":mysqlEnum,
		"drda":drdaEnum,
		"ms-wbt-server":rdpEnum,
		"rmiregistry":rmiEnum
	}
	
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
	]
	menuChoice = ""
	global targets
	while menuChoice != 0:
		menuChoice = executeMenu("","",options)
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
			message = str(count) + " IPs successfully loaded."
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
				message = str(len(addedTargets)) + " IPs successfully loaded."
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
			v = ""
			while v!="y" and v!="n":
				v = input("Do you want to continue? (Y/N): ")
				if len(v) != 0:
					v = v[0].lower()
			if v == "y":
				jobs = [pool.apply_async(nmapScan, args=(ip,nmapOptions["timing"],nmapOptions["verbosity"],nmapOptions["port"],nmapOptions["versioning"],nmapOptions["online"],nmapOptions["TCP"],nmapOptions["OS"],nmapOptions["custom"],nmapOptions["Pn"],nmapOptions["Open"],"TCP")) for ip in targets]
				for p in jobs:
					temp = p.get()
					for key in temp:
						if key in serviceDict:
							serviceDict[key] = serviceDict[key]+ temp[key]
						else:
							serviceDict[key] = temp[key]
		
				subprocess.check_output("cat " + root + "discovery"+sep+"nmap"+sep+"tcp/tcp_*.csv >> " + root + "discovery"+sep+"nmap"+sep+"tcp/tcp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
				subprocess.check_output("echo 'ip,hostname,port,protocol,service,version\n' | cat - " + root + "discovery"+sep+"nmap"+sep+"tcp/tcp_nmap_all.csv > temp && mv temp " + root + "discovery"+sep+"nmap"+sep+"tcp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
			
				if os.path.isfile(root+"serviceDict.dat"):
					os.system("rm " + root + "serviceDict.dat")
				with open(root+"serviceDict.dat","wb") as f:
					pickle.dump(serviceDict, f)
					f.close()
				logger.info("NMAP Scans complete for all ips.  inidividual results in discovery/nmap full results in discovery/nmap/tcp_nmap_all.csv")
				v = ""
				while v!="y" and v!="n":
					v = input("Would you like to open the results file? (Y/N): ")
					if len(v) != 0:
						v = v[0].lower()
				if v == "y":
					CMD = "/usr/bin/leafpad " + root + "discover/nmap/nmap_all.csv"
					subprocess.check_output(CMD.split(" "), stderr=subprocess.STDOUT)
				logger.info("Log data available at " + root + "reconscan.log")
				input("Press Enter to continue.")
		
		elif menuChoice == 3:
			logger.info("You are about to run an NMAP scan.  You cannot close this window until it is finished.")
			v = ""
			while v!="y" and v!="n":
				v = input("Do you want to continue? (Y/N): ")
				if len(v) != 0:
					v = v[0].lower()
			if v == "y":
				jobs = [pool.apply_async(nmapScan, args=(ip,nmapOptions["timing"],nmapOptions["verbosity"],nmapOptions["port"],nmapOptions["versioning"],nmapOptions["online"],nmapOptions["TCP"],nmapOptions["OS"],nmapOptions["custom"],nmapOptions["Pn"],nmapOptions["Open"],"TCP")) for ip in targets]
				for p in jobs:
					temp = p.get()
					for key in temp:
						if key in serviceDict:
							serviceDict[key] = serviceDict[key]+ temp[key]
						else:
							serviceDict[key] = temp[key]

				subprocess.check_output("cat " + root + "discovery"+sep+"nmap"+sep+"udp/udp*.csv >> " + root + "discovery"+sep+"nmap"+sep+"udp/udp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
				subprocess.check_output("echo 'ip,hostname,port,protocol,service,version\n' | cat - " + root + "discovery"+sep+"nmap"+sep+"udp/udp_nmap_all.csv > temp && mv temp " + root + "discovery"+sep+"nmap"+sep+"udp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
			
				if os.path.isfile(root+"serviceDict.dat"):
					os.system("rm " + root + "serviceDict.dat")
				with open(root+"serviceDict.dat","wb") as f:
					pickle.dump(serviceDict, f)
					f.close()
				logger.info("NMAP Scans complete for all ips.  inidividual results in discovery/nmap full results in discovery/nmap/udp_nmap_all.csv")
				
				while v!="y" and v!="n":
					v = input("Would you like to open the results file? (Y/N): ")
					if len(v) != 0:
						v = v[0].lower()
				if v == "y":
					CMD = "/usr/bin/leafpad " + root + "discover/nmap/nmap_all.csv"
					subprocess.check_output(CMD.split(" "), stderr=subprocess.STDOUT)
				logger.info("Log data available at " + root + "reconscan.log")
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
						pool.apply_async(enumWorker, args=(serv[0], serv[1], choice), callback=enumCallback)
	
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
							jobs.append(pool.apply_async(enumWorker, args=(serv[0], serv[1], services)))
				
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
				for serv in knownServices:
					if serv in serviceDict:
						count += 1
				if count == 0:
					message = "No discovered services are guessable."
				else:
					print("Type the full name of the service you would like to guess or press 0 to go back")
					while choice not in knownServices and choice != "0":
						for serv in knownServices:
							if serv in serviceDict:
								print (serv)
						choice = input('>>')
					if choice != "0":
						logger.info("Starting guess for " + choice)
						for serv in serviceDict[choice]:
							pwCounter[choice] += 1
							pwCounter["total"] += 1
							pool.apply_async(pwWorker, args=(serv[0], serv[1], choice, medusaFlags), callback = pwCallback)
					
					input("Press ENTER to go back to the main menu\n\n")

		elif menuChoice == 3:
			if serviceDict == {}:
				message = "No services detected: Please run NMAP scans first"
			else:
				logger.info("No PW guess tool for the following services: ")
				for serv in serviceDict:
					if serv not in knownServices:
						for ips in serviceDict[serv]:
							temp = ips[0]+":"+ips[1]+" "
						logger.info(" -"+serv+": "+ temp)
			
				logger.info("Starting Guessing on all possible services")
				jobs = []
				for services in knownServices:
					if services in serviceDict:
						for serv in serviceDict[services]:
							jobs.append(pool.apply_async(pwWorker, args=(serv[0], serv[1], choice, medusaFlags), callback = pwCallback))
							
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
		"Set respondeing ip",
		"Set responder location"
	]
	flags = "vbwFr"
	interface = "eth0"
	rip = ""
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
		if rip != "":
			t2 = "-i " + rip
		if flags != "":
			t3 = "-" + flags
		title = "python " + loc + " " + t3 + " " + t2 + " " + t1
		menuChoice = executeMenu(title,message,options)
		if menuChoice == 1:
			if rip != "":
				RESPONDER = "gnome-terminal -x " + title
				logger.info("Running Responder")
				subprocess.check_output(RESPONDER.split(" "), stderr=subprocess.STDOUT)
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
		elif menuChoice == 4:
			v = "n"
			while v!="y":
				temp = input("Enter the responding IP: ")
				print (temp)
				v = input("Is this correct? (Y/N): ")
				if len(v) != 0:
					v = v[0].lower()
			rip = temp
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
		"Display findings by IP"
	]
	title = ""
	message = ""
	menuChoice = ""
	while menuChoice != 0:
		menuChoice = executeMenu(title,message,options)
		if menuChoice == 1:
			CMD = "/usr/bin/leafpad "+ root + "findings.csv"
			logging.info("Opening " + root + "findings.csv")
			subprocess.check_output(CMD.split(" "))
		elif menuChoice == 2:
			fi = open(root + "findings.csv", "r")
			count = 1
			logging.info("Showing all findings")
			while line == fi.readline():
				line = line.split(",")
				print (line[3] + " found on " + line[0] + ":"  + line[1])
				if count % 10 == 0:
					input ("Press any continue to continue")
				count = count + 1
			fi.close()
		elif menuChoice == 3:
			fi = open(root + "findings.csv", "r")
			count = 1
			ip = "123"
			while not re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip.strip()):
				ip = input("Enter a valid ip address: ")
			
			logging.info("Showing findings for" + ip)
			while line == fi.readline():
				line = line.split(",")
				if line[0] == ip:
					print (line[3] + " found on " + line[0] + ":" + line[1])
					if count % 10 == 0:
						input ("Press any continue to continue")
					count = count + 1
			fi.close()
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
		ports = "21,22,23,25,42,53,80,88,110,111,135,139,143,389,397,443,445,446,447,448,449,512,513,514,515,523,548,554,992,993,995,1080,1125,1159,1352,1433,1494,1521,1522,1523,1524,1525,1526,1761,1993,2000,2001,2010,2049,2100,2103,3000,3268,3306,3389,3527,3632,3690,4001,4105,4848,5010,5040,5060,5432,5544,5555,5566,5631,5632,5800,5900,5985,6000,6001,6050,6070,6101,6106,6112,6129,8000,8008,8009,8080,8085,8088,8090,8105,8109,8180,8222,8333,8443,8470,8471,8472,8473,8474,8475,8476,8480,8888,9001,9084,9087,9100,9470,9471,9472,9473,9474,9475,9476,9480,9999,10000,10202,10203,20031,41523,41524"
	elif port == "Moderate":
		ports = "1-3,5,7,9,11,13,15,17-25,27,29,31,33,35,37-39,41-223,242-246,256-265,280-282,309,311,318,322-325,344-351,363,369-581,587,592-593,598,600,606-620,624,627,631,633-637,666-674,700,704-705,707,709-711,729-731,740-742,744,747-754,758-765,767,769-777,780-783,786,799-801,860,873,886-888,900-901,911,950,954-955,990-993,995-1001,1008,1010-1011,1015,1023-1100,1109-1112,1114,1123,1155,1167,1170,1207,1212,1214,1220-1222,1234-1236,1241,1243,1245,1248,1269,1313-1314,1337,1344-1625,1636-1774,1776-1815,1818-1824,1900-1909,1911-1920,1944-1951,1973,1981,1985-2028,2030,2032-2036,2038,2040-2049,2053,2065,2067,2080,2097,2100,2102-2107,2109,2111,2115,2120,2140,2160-2161,2201-2202,2213,2221-2223,2232-2239,2241,2260,2279-2288,2297,2301,2307,2334,2339,2345,2381,2389,2391,2393-2394,2399,2401,2433,2447,2500-2501,2532,2544,2564-2565,2583,2592,2600-2605,2626-2627,2638-2639,2690,2700-2702,2716,2766,2784-2789,2801,2908-2912,2953-2954,2967,2998,3000-3002,3006-3007,3010-3011,3020,3047-3049,3080,3127-3128,3141-3145,3180-3181,3205,3232,3260,3264,3267-3269,3279,3306,3322-3325,3333,3340,3351-3352,3355,3372,3389,3421,3454-3457,3689-3690,3700,3791,3900,3984-3986,4000-4002,4008-4009,4080,4092,4100,4103,4105,4107,4132-4134,4144,4242,4321,4333,4343,4443-4454,4500-4501,4567,4590,4626,4651,4660-4663,4672,4899,4903,4950,5000-5005,5009-5011,5020-5021,5031,5050,5053,5080,5100-5101,5145,5150,5190-5193,5222,5236,5300-5305,5321,5400-5402,5432,5510,5520-5521,5530,5540,5550,5554-5558,5569,5599-5601,5631-5632,5634,5650,5678-5679,5713-5717,5729,5742,5745,5755,5757,5766-5767,5800-5802,5900-5902,5977-5979,5997-6053,6080,6103,6110-6112,6123,6129,6141-6149,6253,6346,6387,6389,6400,6455-6456,6499-6500,6515,6543,6558,6588,6660-6670,6672-6673,6699,6767,6771,6776,6789,6831,6883,6912,6939,6969-6970,7000-7021,7070,7080,7099-7100,7121,7161,7174,7200-7201,7300-7301,7306-7308,7395,7426-7431,7491,7511,7777-7778,7781,7789,7895,7938,7999-8020,8023,8032,8039,8080-8082,8090,8100,8181,8192,8200,8383,8403,8443,8450,8484,8732,8765,8886-8894,8910,9000-9002,9005,9043,9080,9090,9098-9100,9400,9443,9495,9535,9570,9872-9876,9878,9889,10005,10007,10080-10082,10101,10202,10204,10520,10607,10666,11000-11002,11004,11223,12000-12002,12076,12223,12287,12345-12346,12361-12362,12456,12468-12469,12631,12701,12753,13000,13333,14237-14238,15858,16384,16660,16959,16969,17000,17007,17300,18000,18181-18186,18190-18192,18194,18209-18210,18231-18232,18264,19541,20000-20001,20011,20034,20200,20203,20331,21544,21554,21845-21849,22222,22273,22289,22305,22321,22555,22800,22951,23456,23476-23477,25000-25009,25252,25793,25867,26000,26208,26274,26409,27000-27009,27374,27665,29369,29891,30029,30100-30102,30129,30303,30999,31336-31337,31339,31554,31666,31785,31787-31788,32000,32768-32790,33333,33567-33568,33911,34324,37651,40412,40421-40423,42424,44337,47557,47806,47808,49400,50505,50766,51102,51107,51112,53001,54320-54321,57341,60008,61439,61466,62078,65000,65301,65512"
	else:
		ports = "0-65535"

	ip_address = ip_address.strip()
	ip_format = ip_address.replace("/", "_")
	TCPSCAN = "nmap -" + verbosity + " -T " + str(timing) + " -p " + ports + " -s" + TCP + versioning + " " + Pn + " " + Open + " " + OS + custom +" -oA " + root + "discovery/nmap/tcp/tcp_%s %s"  % (ip_format, ip_address)
	UDPSCAN = "nmap -" + verbosity + " -T " + str(timing) + " -p " + ports + " -s" + TCP + versioning + " " + Pn + " " + Open + " " + OS + custom +" -oA " + root + "discovery/nmap/tcp/udp_%s %s"  % (ip_format, ip_address)
	tempDict = {}

	if type == "TCP":
		logging.info("Running TCP nmap scans for " + ip_address)
		try:
			subprocess.check_output(TCPSCAN, shell=True, stderr=subprocess.STDOUT)
			try:
				fo = open(root + "discovery"+sep+"nmap"+sep+"tcp/tcp_"+ip_format+".csv", 'w+')
				tempDict = nmapparser.process(root+"discovery"+sep+"nmap"+sep+"tcp/tcp_"+ip_format+".xml", fo)
				fo.close()
			except:
				logging.error ("Error Processing NMAP Results.  Nmap scans still available at /discover/nmap/tcp")
		except:
			logging.error("Error running NMAP scans")
		
		
	if type == "UDP":
		logging.info("Running UDP nmap scans for " + ip_address)
		try:
			subprocess.check_output(UDPSCAN, shell=True, stderr=subprocess.STDOUT)
			try:
				fo = open(root + "discovery"+sep+"nmap"+sep+"udp/udp_"+ip_format+".csv", 'w+')
				fo.close()
				tempDict = nmapparser.process(root+"discovery"+sep+"nmap"+sep+"udp/udp_"+ip_format+".xml", fo)
			except:
				logging.error ("Error Processing NMAP Results.  Nmap scans still available at /discover/nmap/tcp")
		except:
			logging.error("Error running NMAP scans")

	logging.info(type + " Nmap scans completed for " + ip_address)
	return tempDict		
				
##########################################################
# Enum functions
##########################################################

def drdaEnum(ip_address, port, service):
	logging.info("Detected DRDA on " + ip_address + ":" + port)
	logging.info("Performing nmap DRDA script scan for " + ip_address + ":" + port)
	DRDASCAN = nse.DRDA(ip_address, port)	
	try:
		nseout = subprocess.check_output(DRDASCAN.split(' '))
		resultsfile = root + "discovery/drda/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for DRDA " + ip + ":"+ port)
	return [service, ip_address, port]
	
def rdpEnum(ip_address, port, service):
	logging.info("Detected RDP on " + ip_address + ":" + port)
	logging.info("Performing nmap RDP script scan for " + ip_address + ":" + port)
	RDPSCAN = nse.Remote_Desktop(ip_address, port)	
	try:
		nseout = subprocess.check_output(RDPSCAN.split(' '))
		resultsfile = root + "discovery/rdp/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for RDP " + ip + ":"+ port)
	return [service, ip_address, port]
	
def rmiEnum(ip_address, port, service):
	logging.info("Detected JAVA RMI on " + ip_address + ":" + port)
	logging.info("Performing nmap RMI script scan for " + ip_address + ":" + port)
	RMISCAN = nse.RMI_Registry(ip_address, port)	
	try:
		nseout = subprocess.check_output(RMISCAN.split(' '))
		resultsfile = root + "discovery/rmi/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for DRDA " + ip + ":"+ port)
	return [service, ip_address, port]

def dnsEnum(ip_address, port, service):
	logging.info("Detected DNS on " + ip_address + ":" + port)
	if port.strip() == "53":
		dnsrecon.main(["",ip_address, root])
	else:
		logging.error("Can only run dns enum on port 53")
	
	logging.info("Performing nmap DNS script scan for " + ip_address + ":" + port)
	DNSSCAN = nse.DNS(ip_address, port)	
	try:
		nseout = subprocess.check_output(DNSSCAN, shell=True)
		resultsfile = root + "discovery/dns/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for snmp " + ip + ":"+ port)
	return [service, ip_address, port]

def httpEnum(ip_address, port, service):
	logging.info("Detected http on " + ip_address + ":" + port)
	logging.info("Performing nmap web script scan for " + ip_address + ":" + port + " see directory/http for results")
	#HTTPSCAN = "nmap -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN discovery/http/%s_http.nmap %s" % (port, ip_address, ip_address)
	HTTPSCAN = nse.http(ip_address, port)
	try:
		nseout = subprocess.check_output(HTTPSCAN, shell=True)
		resultsfile = root + "discovery/http/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for http " + ip + ":"+ port)

	logging.info("Using Dirbuster for " + ip_address + ":" + port + " see directory/http for results")
	dirbust.main(["",ip_address,port,False])

	logging.info("Performing NIKTO scan for " + ip_address + ":" + port + " see directory/http for results")
	NIKTOSCAN = "nikto -host %s -p %s" % (ip_address, port)
	try:
		NIKTOSCAN = subprocess.check_output(NIKTOSCAN, shell=True)
		out = "discover/http/" + ip_address + "NIKTO.txt"
		niktoout = open(out, "w+")
		niktoout.write(NIKTOSCAN)
		niktoout.close()
	except:
		logging.error("NIKTO failed for " + ip + ":"+ port)
	return  [service, ip_address, port]

def httpsEnum(ip_address, port, service):
	logging.info("Detected https on " + ip_address + ":" + port)
	logging.info("Performing nmap web script scan for " + ip_address + ":" + port)
	HTTPSSCAN = "nmap -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN discovery/http/%s_https.nmap %s" % (port, ip_address, ip_address)
	try:
		nseout = subprocess.check_output(HTTPSSCAN, shell=True)
		resultsfile = root + "discovery/http/" + ip + ":" + port + "_ssl_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for https " + ip + ":"+ port)

	logging.info("Using Dirbuster for " + ip_address + ":" + port + " see directory/http for results")
	dirbust.main(["",ip_address,port, True])

	logging.info("Performing NIKTO scan for " + ip_address + ":" + port + " see directory/http for results")
	NIKTOSCAN = "nikto -host %s -p %s" % (ip_address, port)
	try:
		NIKTOSCAN = subprocess.check_output(NIKTOSCAN, shell=True)
		out = "discover/http/" + ip_address + "NIKTO_SSL.txt"
		niktoout = open(out, "w+")
		niktoout.write(NIKTOSCAN)
		niktoout.close()
	except:
		logging.error("NIKTO failed for " + ip + ":"+ port)
	return  [service, ip_address, port]

def mssqlEnum(ip_address, port, service):
	logging.info("Detected MS-SQL on " + ip_address + ":" + port)
	logging.info("Performing nmap mssql script scan for " + ip_address + ":" + port)
	MSSQLSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,mssql.username-sa,mssql.password-sa -oX discovery/mssql/%s_mssql.xml %s" % (port, ip_address, ip_address)
	try:
		nseout = subprocess.check_output(MSSQLSCAN, shell=True)
		resultsfile = root + "discovery/mssql/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for mssql" + ip + ":"+ port)

	return [service, ip_address, port]

def mysqlEnum(ip_address, port, service):
	logging.info("Detected mySQL on " + ip_address + ":" + port)
	logging.info("Performing nmap mysql script scan for " + ip_address + ":" + port)
	# mysql-vuln-cve2012-2122
	MYSQLSCAN = "nmap -vv -sV -Pn -p %s --script=mysql-enum, mysql-empty-password  -oX discovery/mysql/%s_mysql.xml %s" % (port, ip_address, ip_address)
	try:
		nseout = subprocess.check_output(MYSQLSCAN, shell=True)
		resultsfile = root + "discovery/mysql/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for mysql" + ip + ":"+ port)


	return [service, ip_address, port]

def sshEnum(ip_address, port, service):
	logging.info("Detected SSH on " + ip_address + ":" + port)
	# sshrecon.main(["", ip_address, port])				 NOTHING HERE YET
	logging.info("Performing nmap SSH script scan for " + ip_address + ":" + port)
	SSHSCAN = nse.SSH(ip_address, port)	
	try:
		nseout = subprocess.check_output(SSHSCAN, shell=True)
		resultsfile = root + "discovery/ssh/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for ssh " + ip + ":"+ port)
	return [service, ip_address, port]

def snmpEnum(ip_address, port, service):
	logging.info("Detected snmp on " + ip_address + ":" + port)
	snmprecon.main(["", ip_address, root])
	
	logging.info("Performing nmap snmp script scan for " + ip_address + ":" + port)
	SNMPSCAN = nse.SNMP(ip_address, port)	
	try:
		nseout = subprocess.check_output(SNMPSCAN, shell=True)
		resultsfile = root + "discovery/snmp/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for snmp " + ip + ":"+ port)
		
	return [service, ip_address, port]

def smtpEnum(ip_address, port, service):
	logging.info("Detected smtp on " + ip_address + ":" + port)
	smtprecon.main(["", ip_address, port])
	
	logging.info("Performing nmap smtp script scan for " + ip_address + ":" + port)
	SMTPSCAN = nse.SMTP(ip_address, port)	
	try:
		nseout = subprocess.check_output(SMTPSCAN, shell=True)
		resultsfile = root + "discovery/smtp/" + ip + ":" + port + "_nse.txt"
		f = open(resultsfile, "w")
		f.write(nseout)
		f.close
	except:
		logging.error("NSE failed for smtp " + ip + ":"+ port)
		
	return [service, ip_address, port]

def smbEnum(ip_address, port, service):
	logging.info("Detected SMB on " + ip_address + ":" + port)
	smbrecon.main(["",ip_address, port,root])
	return [service, ip_address, port]

def ftpEnum(ip_address, port, service):
	logging.info("Detected ftp on " + ip_address + ":" + port)
	ftprecon.main(["",ip_address,port,root])

	return [service, ip_address, port]
	
##########################################################
# PW Guess functions
##########################################################
		
def httpPW(ip, port, service, options):
	logging.info("Starting password guess for http web form at " + ip + ":" + port)
	medusa.webformCrack(ip, port, root, options)
	logging.info("Password guess for http at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]
	
def sshPW(ip, port, service, options):
	logging.info("Starting password guess for ssh  at " + ip + ":" + port)
	medusa.sshCrack(ip, port, root, options)
	logging.info("Password guess for ssh at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]
	
def ftpPW(ip, port, service, options):
	logging.info("Starting password guess for ftp at " + ip + ":" + port)
	medusa.ftpCrack(ip, port, root, options)
	logging.info("Password guess for ftp at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]

def mssqlPW(ip, port, service, options):
	logging.info("Starting password guess for MS SQL at " + ip + ":" + port)
	medusa.mssqlCrack(ip, port, root, options)
	logging.info("Password guess for mssql at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]

def mysqlPW(ip, port, service, options):
	logging.info("Starting password guess for MySQL at " + ip + ":" + port)
	medusa.mysqlCrack(ip, port, root, options)
	logging.info("Password guess for mysql at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]
	
def vncPW(ip, port, service, options):
	logging.info("Starting password guess for VNC at " + ip + ":" + port)
	medusa.vncCrack(ip, port, root, options)
	logging.info("Password guess for vnc at " + ip + ":" + port + " has completed.  See " + root + "password/ for more details")
	return [service, ip, port]

##########################################################
# Utility functions
##########################################################

def enumWorker(ip, port, service):
	qh = logging.handlers.QueueHandler(q)
	root = logging.getLogger()
	root.setLevel(logging.DEBUG)
	root.addHandler(qh)
	
	knownServices[service](ip, port, service)
	return [service, ip, port]
	
def pwWorker(ip, port, service, options):
	qh = logging.handlers.QueueHandler(q)
	root = logging.getLogger()
	root.setLevel(logging.DEBUG)
	root.addHandler(qh)
	
	knownPwServices[service](ip, port, service, options)
	return [service, ip, port]
	
def logger_thread(q):
	while True:
		record = q.get()
		if record is None:
			break
		logger = logging.getLogger('sh0tgun_logger')
		logger.handle(record)

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
	logging.info ("Enumeration of " + retVal[0] + " has completed for " +retVal[1] + ":" + retVal[2])
	if enumCounter[retVal[0] ] == 0:
		logging.info ("Enumeration of all " + retVal[0] + " instances has completed. See " + root + "discovery/ for details")
		input("\nPress Enter to continue.  Log data available at " + root + "reconscan.log")
	if enumCounter["total"] == 0:
		logging.info ("Guessing of all services has completed. See " + root + "discovery/ for details")
		input("\nPress Enter to continue.  Log data available at " + root + "reconscan.log")
	
def pwCallback(retVal):
	global pwCounter
	pwCounter[retVal[0] ] -= 1
	logging.info ("Guessing of " + retVal[0] + " has completed for " +retVal[1] + ":" + retVal[2])
	if pwCounter[retVal[0] ] == 0:
		logging.info ("Guessing of all " + retVal[0] + " instances has completed. See " + root + "password/ for details")
		input("\nPress Enter to continue.  Log data available at " + root + "reconscan.log")
	if pwCounter["total"] == 0:
		logging.info ("Guessing of all services has completed. See " + root + "password/ for details")
		input("\nPress Enter to continue.  Log data available at " + root + "reconscan.log")
	
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
		lev = logging.WARNING
		print("Log level set to warning")
	elif l < 2:
		lev = logging.CRITICAL
		print("Log level set to critical")
	elif l == 2:
		lev = logging.WARNING
		print("Log level set to warning")
	elif l > 2:
		lev = logging.DEBUG
		print("Log level set to info")
	
	logging.addLevelName(FOUND_LEVEL_NUM, "FOUND")
	logging.Logger.found = found
	
	global logger
	logger = logging.getLogger('sh0tgun_logger')
	logger.setLevel(5)
	fh = logging.FileHandler(root+"sh0tgun.log")
	fh.setLevel(logging.DEBUG)
	
	ch = logging.StreamHandler()
	ch.setLevel(5)
	
	formatter = logging.Formatter('%(levelname)s: %(message)s')
	fh.setFormatter(formatter)
	ch.setFormatter(formatter)
	
	logger.addHandler(fh)
	logger.addHandler(ch)
	
	logger.critical("THIS IS CRITICAL")
	logger.info("THIS IS INFO")
	
	lp = threading.Thread(target=logger_thread, args=(q,))
	lp.start()

def found(self, message, *args, **kws):
	# Yes, logger takes its '*args' as 'args'.
	if self.isEnabledFor(FOUND_LEVEL_NUM):
		self._log(FOUND_LEVEL_NUM, message, args, **kws) 
			
def initDirs():
	# TODO REMOVE
	os.system("rm -r " + root + "discovery")
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
