#!/usr/bin/env python
import sys

if sys.version_info[0] != 3 or sys.version_info[1] < 1:
	print("\nEXIT: This script requires Python version 3.1 or higher\n")
	sys.exit(1)
	
import subprocess
import pickle
import argparse
import re
import os
import math
import scripts.nmapxmltocsv as nmapparser
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

from multiprocessing import Pool

sep = os.path.sep
root = "/root/TEST/"
targets = []
procs = 4
serviceDict = {}
logger = None

def num(s):
	try:
		return int(s)
	except:
		return None
		
def log(str):
	print (str)
	if logger is not None:
		logger.write(str)

def mainMenu(argv):
	menuChoice = ""
	message = ""
	while (menuChoice != "q"):
		print(chr(27) + "[2J")
		print (message + "\n")
		print ("1) Initialize")
		print ("2) Manage Targets")
		print ("3) Run Nmap")
		print ("4) Enumerate Services")
		print ("5) Password Guess")
		print ("6) Exploit")
		
		print ("\nQ) Quit\n")
		menuChoice = input('Option #:')
		
		if menuChoice == '':
			message = "Enter a correct Option"
		elif menuChoice[0].lower != "q":
			temp = num(menuChoice)
			if temp is not None:
				if temp == 1:
					initializeMenu()
				elif temp == 2:
					targetsMenu()
				elif temp == 3:
					if len(targets) == 0:
						message = "There are no targets to scan. Press 2 to add targets"
					elif root == "root":
						message = "Project directory has not been intialized. Press 1 to set root folder and initialize"
					else:
						runNmapMenu()
				elif temp == 4:
					enumServicesMenu()
				elif temp == 5:
					pwMenu()
				elif temp == 6:
					exploitMenu()
				else:
					menuChioce = ""
		
def initializeMenu():
	menuChoice = ""
	message = ""
	while (menuChoice != "q"):
		print(chr(27) + "[2J")
		print (message + "\n")
		print ("1) Select root directory")
		print ("2) Create project directories and logs")
		print ("3) Multi Processing settings")
		
		print ("\n0) Main Menu")
		print ("Q) Quit\n")
		menuChoice = input('>> ')
		message = ""
		if menuChoice == '':
			message = "Enter a correct Option"
		elif menuChoice[0].lower() != "q":
			menuChoice = num(menuChoice)
			if menuChoice is not None:
				if menuChoice == 1:
					global root
			
					r = "/Users/taapes/dev/TEST/"
					while not os.path.exists(r):
						v = "n"
						while v!="y":
							r = input("Enter valid project root folder: ")
							print (r)
							v = input("Is this correct? (Y/N): ")
							v = v[0].lower()
					if r[-1] != "/":
						r = r+"/"
					root = r
					if os.path.isfile(root+"serviceDict.dat"):
						v = input("Previous NMAP Data was found here.  Would you like to load? If not, all previous data will be erased upon directory initialization (2). (Y/N): ")
						if v[0].lower() == "y":
							with open(root+"serviceDict.dat","rb") as f:
								global serviceDict
								serviceDict = pickle.load(f)
					message = "Project root set to: " + root
				elif menuChoice == 2:
					init()
					global logger
					logger = open(root+"reconscan.log", 'w+')
					message = "Project root directories successfully created"
				elif menuChoice == 3:
					global procs
					p = -1
					while p < 1 or math.isnan(p):
						p = int(input("Enter the MAXIMUM number of conncurrent processes to run (default is 4): "))
					procs = p
					message = "Processes set to " + str(procs)
				elif menuChoice == 0:
					menuChoice = "q"
				else:
					message = "Enter a correct option"
			else:
				menuChoice = ""
				message =  "Enter a correct option"
		else:
			menuChoice = ""
			choice = input ("Are you sure you want to quit? (Y/N): ")
			if (choice[0].lower() == "y"):
				sys.exit()
			

def targetsMenu():
	menuChoice = 0
	message = ""
	while (menuChoice != "q"):
		print (chr(27) + "[2J")
		print (message + "\n")
		print ("1) Import Targets from file")
		print ("2) Add targets manually")
		print ("3) Remove targets")
		print ("4) Show targets")
		print ("\n0) Main Menu")
		print ("Q) Quit\n")
		menuChoice = input('Option #:')
		message = ""
		if menuChoice == '':
			message = "Enter a correct Option"
		elif menuChoice[0].lower() != "q":
			menuChoice = num(menuChoice)
			if menuChoice is not None:
				if menuChoice == 1:
					targetfile = ""
					while not os.path.isfile(targetfile):
						print ("Enter the path and file.  Please format the text file with 1 ip per line, no commas or end characters. ")
						targetfile = input(">>")
					f = open(targetfile, 'r')
					global targets
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
					global targets
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
						global targets
						ip = targets.pop(int(remove))
						message = "IP removed: " + ip
				elif menuChoice == 4:
					count = 0
					global targets
					for ip in targets:
						print (ip)
					input("Press ENTER when done")
				elif menuChoice == 0:
					menuChoice = "q"
				else:
					message = "Enter a correct option"
			else:
				menuChoice = ""
				message =  "Enter a correct option"
		else:
			menuChoice = ""
			choice = input ("Are you sure you want to quit? (Y/N): ")
			if (choice[0].lower() == "y"):
				sys.exit()

def runNmapMenu():
	timing = 4
	verbosity = "vvv"
	port = "moderate"
	versioning = "V"
	online = "-Pn"
	TCP = "S"
	OS = "-O"
	custom = ""
	Pn = "-Pn"
	Open = "--open"
	
	pool = Pool(processes=procs)
	
	
	menuChoice = ""
	while (menuChoice != "q"):
		print(chr(27) + "[2J")
		print ("nmap -" + verbosity + " -T " + str(timing) + " -p " + port + " -s" + TCP + versioning + " " + Pn + " " + Open + " " + OS + custom + " -oA " + root + "discovery/nmap/tcp ip")
		print ("1) Set NMAP options")
		print ("2) Run TCP NMAP SCAN")
		print ("3) Run UDP NMAP Scan")
		print ("\n0) Main Menu")
		print ("Q) Quit\n")
		menuChoice = input('Option #:')
		message = ""
		if menuChoice == '':
			message = "Enter a correct Option"
		elif menuChoice[0].lower() != "q":
			menuChoice = num(menuChoice)
			if menuChoice is not None:
				if menuChoice == 1:
					menuChoice2 = -1
					message2 = ""
					while (menuChoice2 != 0):
						print(chr(27) + "[2J")
						print (message2 + "\n")
						print ("nmap -" + verbosity + " -T " + str(timing) + " -p " + port + " -s" + TCP + versioning + " " + Pn + " " + Open + " " + OS + custom + " -oA " + root + "discovery/nmap/tcp ip")
						print ("1) Set Timing -- Current: " + str(timing))
						print ("2) Set Ports -- Current: " + port)
						print ("3) Set verbosity -- Current: " + verbosity)
						print ("4) Set TCP Scan Type -- Current: s" + TCP)
						print ("5) Set Service Versioning -- Current: " + versioning)
						print ("6) Set OS detection -- Current: " + OS)
						print ("7) Treat all hosts online -- Current: " + Pn)
						print ("8) Only show open ports -- Current: " + Open)
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
						elif menuChoice2 == 2:
							print ("1) Full = 0-65535")
							print ("2) Moderate = Top 1000 ports")
							print ("3) light = Top 125 ports")
							p=0
							while math.isnan(p) or p < 1 or p >= 4:
								p = int(input("Enter the number of the scan intensity (1-3)"))
								if p == 1:
									port = "Full"
								elif p == 2:
									port = "Moderate"
								elif p == 3:
									port = "Light"
								else:
									print ("not valid")
						elif menuChoice2 == 3:
							verbosity = ""
							while verbosity != "v" and verbosity != "vv" and verbosity != "vvv":
								verbosity = input("Enter verbosity level (v, vv, or vvv): ")
								verbosity = verbosity.lower()
						elif menuChoice2 == 4:
							TCP= ""
							while TCP!= "S" and TCP!= "T" and TCP!= "A" and TCP!= "W" and TCP!= "M":
								TCP= input("Enter the tcp scan type (S, T, A, W, or M): ")
								TCP= TCP.upper()
						elif menuChoice2 == 5:
							v = input("Do you want to run service versioning? (Y/N): ")
							v = v[0].lower()
							if v == "y":
								versioning = "V"
							else:
								versioning = ""
						elif menuChoice2 == 6:
							v = input("Do you want to run  OS detection? (Y/N): ")
							v = v[0].lower()
							if v == "y":
								OS = "-O"
							else:
								OS = ""
						elif menuChoice2 == 7:
							v = input("Do you want to treat all hosts as online? (Y/N): ")
							v = v[0].lower()
							if v == "y":
								Pn = "-Pn"
							else:
								Pn = ""
						elif menuChoice2 == 8:
							v = input("Do you want to only show open ports? (Y/N): ")
							v = v[0].lower()
							if v == "y":
								Open = "--open"
							else:
								Open = ""
						elif menuChoice2 == 9:
							custom = input("Enter custom flags, space delimited: ")
						elif menuChoice2 != 0:
							message2 = "Enter a correct option"
				elif menuChoice == 2:
					shell = ""
					while shell!="y" and shell!="n":
						shell = input("Do you want to spawn new windows for each nmap scan? (versus running in the background) (Y/N): ")
						shell = shell[0].lower()
			
					print("You are about to run an NMAP scan.  You cannot close this window until it is finished.")
					v = "n"
					while v!="y":
						v = input("Do you want to continue? (Y/N): ")
						v = v[0].lower()
			
					jobs = [pool.apply_async(nmapScan, args=(ip,timing,verbosity,port,versioning,online,TCP,OS,custom,Pn,Open,"TCP",shell)) for ip in targets]
					global serviceDict
					for p in jobs:
						temp = p.get()
						for key in temp:
							if key in serviceDict:
								serviceDict[key] = serviceDict[key]+ temp[key]
							else:
								serviceDict[key] = temp[key]
				
					pool.close()
					pool.join()
				
					subprocess.check_output("cat " + root + "discovery"+sep+"nmap"+sep+"tcp/tcp_*.csv >> " + root + "discovery"+sep+"nmap"+sep+"tcp/tcp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
					subprocess.check_output("echo 'ip,hostname,port,protocol,service,version\n' | cat - " + root + "discovery"+sep+"nmap"+sep+"tcp/tcp_nmap_all.csv > temp && mv temp " + root + "discovery"+sep+"nmap"+sep+"tcp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
					
					if os.path.isfile(root+"serviceDict.dat"):
						os.system("rm " + root + "serviceDict.dat")
					with open(root+"serviceDict.dat","wb") as f:
						pickle.dump(serviceDict, f)
					print("NMAP Scans complete for all ips.  inidividual results in discovery/nmap full results in discovery/nmap/nmap_all.csv")
					input("Press any key to continue.  Log data available at " + root + "reconscan.log")
				elif menuChoice == 3:
					shell = ""
					while shell!="y" and shell!="n":
						shell = input("Do you want to spawn new windows for each nmap scan? (versus running in the background) (Y/N): ")
						shell = shell[0].lower()
				
					print("You are about to run an NMAP scan.  You cannot close this window until it is finished.")
					v = "n"
					while v!="y":
						v = input("Do you want to continue? (Y/N): ")
						v = v[0].lower()
			
					jobs = [pool.apply_async(nmapScan, args=(ip,timing,verbosity,port,versioning,online,TCP,OS,custom,Pn,Open,"UDP",shell)) for ip in targets]
					global serviceDict
					for p in jobs:
						temp = p.get()
						for key in temp:
							if key in serviceDict:
								serviceDict[key] = serviceDict[key]+ temp[key]
							else:
								serviceDict[key] = temp[key]
			
					pool.close()
					pool.join()
	
					subprocess.check_output("cat " + root + "discovery"+sep+"nmap"+sep+"udp/udp*.csv >> " + root + "discovery"+sep+"nmap"+sep+"udp/udp.csv", shell=True, stderr=subprocess.STDOUT)
					subprocess.check_output("echo 'ip,hostname,port,protocol,service,version\n' | cat - " + root + "discovery"+sep+"nmap"+sep+"udp/udp_nmap_all.csv > temp && mv temp " + root + "discovery"+sep+"nmap"+sep+"udp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
					
					if os.path.isfile(root+"serviceDict.dat"):
						os.system("rm " + root + "serviceDict.dat")
					with open(root+"serviceDict.dat","wb") as f:
						pickle.dump(serviceDict, f)
						
					log("NMAP Scans complete for all ips.  inidividual results in discovery/nmap full results in discovery/nmap/nmap_all.csv")
					input("Press any key to continue.  Log data available at " + root + "reconscan.log")
				elif menuChoice == 0:
					menuChoice = "q"
				else:
					message = "Enter a correct option"
			else:
				menuChoice = ""
				message =  "Enter a correct option"
		else:
			menuChoice == ""
			choice = input ("Are you sure you want to quit? (Y/N): ")
			if (choice[0].lower() == "y"):
				sys.exit()

def nmapScan(ip_address,timing,verbosity,port,versioning,online,TCP,OS,custom,Pn,Open,type,shell):
	if port == "Light":
		ports = "21,22,23,25,42,53,80,88,110,111,135,139,143,389,397,443,445,446,447,448,449,512,513,514,515,523,548,554,992,993,995,1080,1125,1159,1352,1433,1494,1521,1522,1523,1524,1525,1526,1761,1993,2000,2001,2010,2049,2100,2103,3000,3268,3306,3389,3527,3632,3690,4001,4105,4848,5010,5040,5060,5432,5544,5555,5566,5631,5632,5800,5900,5985,6000,6001,6050,6070,6101,6106,6112,6129,8000,8008,8009,8080,8085,8088,8090,8105,8109,8180,8222,8333,8443,8470,8471,8472,8473,8474,8475,8476,8480,8888,9001,9084,9087,9100,9470,9471,9472,9473,9474,9475,9476,9480,9999,10000,10202,10203,20031,41523,41524"
	elif port == "Moderate":
		ports = "1-3,5,7,9,11,13,15,17-25,27,29,31,33,35,37-39,41-223,242-246,256-265,280-282,309,311,318,322-325,344-351,363,369-581,587,592-593,598,600,606-620,624,627,631,633-637,666-674,700,704-705,707,709-711,729-731,740-742,744,747-754,758-765,767,769-777,780-783,786,799-801,860,873,886-888,900-901,911,950,954-955,990-993,995-1001,1008,1010-1011,1015,1023-1100,1109-1112,1114,1123,1155,1167,1170,1207,1212,1214,1220-1222,1234-1236,1241,1243,1245,1248,1269,1313-1314,1337,1344-1625,1636-1774,1776-1815,1818-1824,1900-1909,1911-1920,1944-1951,1973,1981,1985-2028,2030,2032-2036,2038,2040-2049,2053,2065,2067,2080,2097,2100,2102-2107,2109,2111,2115,2120,2140,2160-2161,2201-2202,2213,2221-2223,2232-2239,2241,2260,2279-2288,2297,2301,2307,2334,2339,2345,2381,2389,2391,2393-2394,2399,2401,2433,2447,2500-2501,2532,2544,2564-2565,2583,2592,2600-2605,2626-2627,2638-2639,2690,2700-2702,2716,2766,2784-2789,2801,2908-2912,2953-2954,2967,2998,3000-3002,3006-3007,3010-3011,3020,3047-3049,3080,3127-3128,3141-3145,3180-3181,3205,3232,3260,3264,3267-3269,3279,3306,3322-3325,3333,3340,3351-3352,3355,3372,3389,3421,3454-3457,3689-3690,3700,3791,3900,3984-3986,4000-4002,4008-4009,4080,4092,4100,4103,4105,4107,4132-4134,4144,4242,4321,4333,4343,4443-4454,4500-4501,4567,4590,4626,4651,4660-4663,4672,4899,4903,4950,5000-5005,5009-5011,5020-5021,5031,5050,5053,5080,5100-5101,5145,5150,5190-5193,5222,5236,5300-5305,5321,5400-5402,5432,5510,5520-5521,5530,5540,5550,5554-5558,5569,5599-5601,5631-5632,5634,5650,5678-5679,5713-5717,5729,5742,5745,5755,5757,5766-5767,5800-5802,5900-5902,5977-5979,5997-6053,6080,6103,6110-6112,6123,6129,6141-6149,6253,6346,6387,6389,6400,6455-6456,6499-6500,6515,6543,6558,6588,6660-6670,6672-6673,6699,6767,6771,6776,6789,6831,6883,6912,6939,6969-6970,7000-7021,7070,7080,7099-7100,7121,7161,7174,7200-7201,7300-7301,7306-7308,7395,7426-7431,7491,7511,7777-7778,7781,7789,7895,7938,7999-8020,8023,8032,8039,8080-8082,8090,8100,8181,8192,8200,8383,8403,8443,8450,8484,8732,8765,8886-8894,8910,9000-9002,9005,9043,9080,9090,9098-9100,9400,9443,9495,9535,9570,9872-9876,9878,9889,10005,10007,10080-10082,10101,10202,10204,10520,10607,10666,11000-11002,11004,11223,12000-12002,12076,12223,12287,12345-12346,12361-12362,12456,12468-12469,12631,12701,12753,13000,13333,14237-14238,15858,16384,16660,16959,16969,17000,17007,17300,18000,18181-18186,18190-18192,18194,18209-18210,18231-18232,18264,19541,20000-20001,20011,20034,20200,20203,20331,21544,21554,21845-21849,22222,22273,22289,22305,22321,22555,22800,22951,23456,23476-23477,25000-25009,25252,25793,25867,26000,26208,26274,26409,27000-27009,27374,27665,29369,29891,30029,30100-30102,30129,30303,30999,31336-31337,31339,31554,31666,31785,31787-31788,32000,32768-32790,33333,33567-33568,33911,34324,37651,40412,40421-40423,42424,44337,47557,47806,47808,49400,50505,50766,51102,51107,51112,53001,54320-54321,57341,60008,61439,61466,62078,65000,65301,65512"
	else:
		ports = "0-65535"

	ip_address = ip_address.strip()
	TCPSCAN = "nmap -" + verbosity + " -T " + str(timing) + " -p " + ports + " -s" + TCP + versioning + " " + Pn + " " + Open + " " + OS + custom +" -oA " + root + "discovery/nmap/tcp/tcp_%s %s"  % (ip_address, ip_address)
	UDPSCAN = "nmap -" + verbosity + " -T " + str(timing) + " -p " + ports + " -s" + TCP + versioning + " " + Pn + " " + Open + " " + OS + custom +" -oA " + root + "discovery/nmap/tcp/udp_%s %s"  % (ip_address, ip_address)
	
	if type == "TCP":
		log("INFO: Running TCP nmap scans for " + ip_address)
		subprocess.check_output(TCPSCAN, shell=True, stderr=subprocess.STDOUT)
		fo = open(root + "discovery"+sep+"nmap"+sep+"tcp/tcp_"+ip_address+".csv", 'w+')
		serviceDict = nmapparser.process(root+"discovery"+sep+"nmap"+sep+"tcp/tcp_"+ip_address+".xml", fo)
		
	if type == "UDP":
		log("INFO: Running UDP nmap scans for " + ip_address)
		subprocess.check_output(UDPSCAN, shell=True, stderr=subprocess.STDOUT)
		fo = open(root + "discovery"+sep+"nmap"+sep+"udp/udp_"+ip_address+".csv", 'w+')
		serviceDict = nmapparser.process(root+"discovery"+sep+"nmap"+sep+"udp/udp_"+ip_address+".xml", fo)

	log("INFO: " + type + " Nmap scans completed for " + ip_address)
	return serviceDict				
			
def enumServicesMenu():		
	knownServices = {
		"http":httpEnum , 
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
		"mysql":mysqlEnum
	}
	
	pool = Pool(processes=procs)
	message = ""	
	menuChoice = ""
	while (menuChoice != "q"):
		print(chr(27) + "[2J")
		print (message + "\n")
		print ("1) Show All discovered Services")
		print ("2) Enumerate specific service")
		print ("3) Enumerate All")
		print ("\n0) Main Menu")
		print ("Q) Quit\n")
		menuChoice = input('Option #:')
		
		message = ""
		if menuChoice == '':
			message = "Enter a correct Option"
		elif menuChoice[0].lower() != "q":
			menuChoice = num(menuChoice)
			if menuChoice is not None:
				if menuChoice == 1:
					for serv in serviceDict:
						if serv in knownServices:
							print ("**"+serv)
						else:
							print (serv)
					print ("\n** indicates enumerable services")
					input ("Press any key to return...")
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
							log("INFO: Starting enumeration for " + choice)
							for serv in serviceDict[choice]:
								pool.apply_async(knownServices[choice], args=(serv[0], serv[1]))
							pool.close()
							pool.join()
							log("INFO: Enumeration of " + choice + " has completed. See " + root + "discovery/ for details")
							input("Press any key to continue.  Log data available at " + root + "reconscan.log")
			
				elif menuChoice == 3:
					if serviceDict == {}:
						message = "No services detected: Please run NMAP scans first"
					else:
						log("No enum tool for the following services: ")
						for serv in serviceDict:
							if serv not in knownServices:
								for ips in serviceDict[serv]:
									temp = ips[0]+":"+ips[1]+" "
								log(" -"+serv+": "+ temp)
					
						log("Starting Enumeration")
						for services in knownServices:
							if services in serviceDict:
								for serv in serviceDict[services]:
									pool.apply_async(knownServices[services], args=(serv[0], serv[1]))
						pool.close()
						pool.join()
						log("INFO: Enumeration has completed. See " + root + "discovery/ for details")
						input("Press any key to continue.  Log data available at " + root + "reconscan.log")
			
				elif menuChoice == 0:
					menuChoice = "q"
				else:
					message = "Enter a correct option"
			else:
				menuChoice = ""
				message =  "Enter a correct option"
		else:
			menuChoice == ""
			choice = input ("Are you sure you want to quit? (Y/N): ")
			if (choice[0].lower() == "y"):
				sys.exit()
	return
	
def exploitMenu():
	pass

def init():
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
	return

def checkandmk(path):
	if not os.path.exists(path):
		os.makedirs(path)


def dnsEnum(ip_address, port):
	print("INFO: Detected DNS on " + ip_address + ":" + port)
	if port.strip() == "53":
		dnsrecon.main(["",ip_address])
	return

def httpEnum(ip_address, port):
	print("INFO: Detected http on " + ip_address + ":" + port)
	print("INFO: Performing nmap web script scan for " + ip_address + ":" + port + " see directory/http for results")
	#HTTPSCAN = "nmap -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN discovery/http/%s_http.nmap %s" % (port, ip_address, ip_address)
	HTTPSCAN = nse.http(ip_address, port)
	subprocess.check_output(HTTPSCAN, shell=True)

	print("INFO: Using Dirbuster for " + ip_address + ":" + port + " see directory/http for results")
	dirbust.main(["",ip_address,port])

	# print("INFO: Performing NIKTO scan for " + ip_address + ":" + port + " see directory/http for results")
	# NIKTOSCAN = "nikto -host %s -p %s" % (ip_address, port)
	# NIKTOSCAN = subprocess.check_output(NIKTOSCAN, shell=True)
	# out = "discover/http/" + ip_address + "NIKTO.txt"
	# niktoout = open(out, "w+")
	# niktoout.write(NIKTOSCAN)
	# niktoout.close()
	return 0

def httpsEnum(ip_address, port, root):
	print("INFO: Detected https on " + ip_address + ":" + port)
	print("INFO: Performing nmap web script scan for " + ip_address + ":" + port)
	HTTPSSCAN = "nmap -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN discovery/http/%s_https.nmap %s" % (port, ip_address, ip_address)
	subprocess.check_output(HTTPSSCAN, shell=True)

	print("INFO: Using Dirbuster for " + ip_address + ":" + port + " see directory/http for results")
	dirbust.main(["",ip_address,port])

	# print("INFO: Performing NIKTO scan for " + ip_address + ":" + port + " see directory/http for results")
	# NIKTOSCAN = "nikto -host %s -p %s" % (ip_address, port)
	# NIKTOSCAN = subprocess.check_output(NIKTOSCAN, shell=True)
	# out = "discover/http/" + ip_address + "NIKTO.txt"
	# niktoout = open(out, "w+")
	# niktoout.write(NIKTOSCAN)
	# niktoout.close()
	return

def mssqlEnum(ip_address, port):
	print("INFO: Detected MS-SQL on " + ip_address + ":" + port)
	print("INFO: Performing nmap mssql script scan for " + ip_address + ":" + port)
	MSSQLSCAN = "nmap -vv -sV -Pn -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,mssql.username-sa,mssql.password-sa -oX discovery/mssql/%s_mssql.xml %s" % (port, ip_address, ip_address)
	subprocess.check_output(MSSQLSCAN, shell=True)

	return

def mysqlEnum(ip_address, port):
	print("INFO: Detected mySQL on " + ip_address + ":" + port)
	print("INFO: Performing nmap mysql script scan for " + ip_address + ":" + port)
	# mysql-vuln-cve2012-2122
	MYSQLSCAN = "nmap -vv -sV -Pn -p %s --script=mysql-enum, mysql-empty-password  -oX discovery/mysql/%s_mysql.xml %s" % (port, ip_address, ip_address)
	subprocess.check_output(MYSQLSCAN, shell=True)

	return

def sshEnum(ip_address, port):
	print("INFO: Detected SSH on " + ip_address + ":" + port)
	sshrecon.main(["", ip_address, port])
	
	return

def snmpEnum(ip_address, port):
	print("INFO: Detected snmp on " + ip_address + ":" + port)
	snmprecon.main(["", ip_address])
	return

def smtpEnum(ip_address, port):
	print("INFO: Detected smtp on " + ip_address + ":" + port)
	if port.strip() == "25":
		smtprecon.main(["", ip_address])
	else:
		print("WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)")
	return

def smbEnum(ip_address, port):
	print("INFO: Detected SMB on " + ip_address + ":" + port)
	smbrecon.main(["",ip_address, port,root])
	return

def ftpEnum(ip_address, port):
	print("INFO: Detected ftp on " + ip_address + ":" + port)
	ftprecon.main(["",ip_address,port])

	return


if __name__=='__main__':
	mainMenu(sys.argv)
