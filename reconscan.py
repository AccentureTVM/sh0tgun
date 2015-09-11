#!/usr/bin/env python

import subprocess
import argparse
import os
import sys
import scripts.nmapxmltocsv as nmapparser
import scripts.dirbust as dirbust
import scripts.dnsrecon as dnsrecon
import scripts.ftprecon as ftprecon
import scripts.smbrecon as smbrecon
import scripts.smtprecon as smtprecon
import scripts.snmprecon as snmprecon
import scripts.sshrecon as sshrecon
import scripts.medusa as medusa

from multiprocessing import Pool

crackPWs = False
useMSF = False
sep = os.path.sep
TCP = False
UDP = False

def main(argv):
    parser = argparse.ArgumentParser(description="Scan and Enumerate all services on a network")
    parser.add_argument('-i', '--intensity', default=3, help='1, 2, 3 for light, medium, or heavy port scan respectively. default is 3 (all)')
    parser.add_argument('-c', '--crackPWs', default=False, action='store_true', help='Use medusa to crack passwords for known services')
    parser.add_argument('-m', '--metasploit', default=False, action='store_true', help="Use metasploit modules for enumeration")
    parser.add_argument('-p', '--processes', default=4, help='Number of concurrent processes to run. default = 4')
    parser.add_argument('-u', '--udpscan', default=False, action='store_true', help="Run UDP Scan")
    parser.add_argument('-t', '--tcpscan', default=False, action='store_true', help="Run TCP Scan")
    

    args = parser.parse_args()
    portarg = args.intensity
    global crackPWs
    crackPWs = args.crackPWs
    global useMSF
    useMSF = args.metasploit
    procs=args.processes
    global TCP
    TCP = args.tcpscan
    global UDP
    UDP - args.udpscan

    init()
    f = open('targets.txt', 'r')
    # multiprocessing
    pool = Pool(processes=procs)
    jobs = [pool.apply_async(nmapScan, args=(ip,portarg)) for ip in f]
    serviceDict = {}
    
    for p in jobs:
        temp = p.get()
        for key in temp:
            if key in serviceDict:
                serviceDict[key] = serviceDict[key]+ temp[key]
            else:
                serviceDict[key] = temp[key]

    subprocess.check_output("cat discovery"+sep+"nmap"+sep+"tcp_*.csv >> discovery"+sep+"nmap"+sep+"tcp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
    subprocess.check_output("cat discovery"+sep+"nmap"+sep+"udp_*.csv >> discovery"+sep+"nmap"+sep+"udp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
    subprocess.check_output("echo 'ip,hostname,port,protocol,service,version\n' | cat - discovery"+sep+"nmap"+sep+"tcp_nmap_all.csv > temp && mv temp discovery"+sep+"nmap"+sep+"tcp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)
    subprocess.check_output("echo 'ip,hostname,port,protocol,service,version\n' | cat - discovery"+sep+"nmap"+sep+"udp_nmap_all.csv > temp && mv temp discovery"+sep+"nmap"+sep+"udp_nmap_all.csv", shell=True, stderr=subprocess.STDOUT)

    print("NMAP Scans complete for all ips.  inidividual results in discovery/nmap full results in discovery/nmap/nmap_all.csv")

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
        "ms-sql":mssqlEnum, 
        "mysql":mysqlEnum
    }

    print("No enum tool for following services:")
    for serv in serviceDict:
        if serv not in knownServices:
            print(" -"+serv)

    jobs = []
    # go through the service dictionary to call additional targeted enumeration functions
    for services in serviceDict:
        if services in knownServices:
            print("calling enum for "+str(knownServices[services]))
            print("services")
            for serv in services:
            	jobs.append(pool.apply_async(knownServices[services], args=(serv[0], serv[1])))
            	
    for p in jobs:
        p.get()

    f.close()
    return

def init():
    # TODO REMOVE
    os.system("rm -r discovery")
    checkandmk('discovery')
    checkandmk('discovery'+sep+'dirb')
    checkandmk('discovery'+sep+'dns')
    checkandmk('discovery'+sep+'ftp')
    checkandmk('discovery'+sep+'smb')
    checkandmk('discovery'+sep+'smtp')
    checkandmk('discovery'+sep+'snmp')
    checkandmk('discovery'+sep+'ssh')
    checkandmk('discovery'+sep+'mssql')
    checkandmk('discovery'+sep+'db2')
    checkandmk('discovery'+sep+'oracle')
    checkandmk('discovery'+sep+'nmap')
    checkandmk('discovery'+sep+'http')
    checkandmk('discovery'+sep+'vnc')
    checkandmk('discovery'+sep+'mysql')
    checkandmk('issues')
    checkandmk('lists')
    checkandmk('password')
    checkandmk('pillage')
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
    HTTPSCAN = "nmap -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN discovery/http/%s_http.nmap %s" % (port, ip_address, ip_address)
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
    return

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

    if crackPWs:
        print("INFO: Performing Medusa MSSQL Password crack for " + ip_address + ":" + port + " see directory/mssql for results")
        medusa.mssqlCrack(ip_address, port)
    return

def mysqlEnum(ip_address, port):
    print("INFO: Detected mySQL on " + ip_address + ":" + port)
    print("INFO: Performing nmap mysql script scan for " + ip_address + ":" + port)
    # mysql-vuln-cve2012-2122
    MYSQLSCAN = "nmap -vv -sV -Pn -p %s --script=mysql-enum, mysql-empty-password  -oX discovery/mysql/%s_mysql.xml %s" % (port, ip_address, ip_address)
    subprocess.check_output(MYSQLSCAN, shell=True)

    if crackPWs:
        print("INFO: Performing Medusa mySQL Password crack for " + ip_address + ":" + port + " see directory/mysql for results")
        medusa.mysqlCrack(ip_address, port)
    return

def sshEnum(ip_address, port):
    print("INFO: Detected SSH on " + ip_address + ":" + port)
    sshrecon.main(["", ip_address, port])
    if crackPWs:
        print("INFO: Performing Medusa ssh Password crack for " + ip_address + ":" + port + " see directory/ssh for results")
        medusa.sshCrack(ip_address, port)
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
    smbrecon.main(["",ip_address])
    return

def ftpEnum(ip_address, port):
    print("INFO: Detected ftp on " + ip_address + ":" + port)
    ftprecon.main(["",ip_address])
    if crackPWs:
        print("INFO: Performing Medusa FTP Password crack for " + ip_address + ":" + port + " see directory/ftp for results")
        medusa.ftpCrack(ip_address, port)
    return

def nmapScan(ip_address,portnum):
    if portnum == "1":
        ports = "21,22,23,25,42,53,80,88,110,111,135,139,143,389,397,443,445,446,447,448,449,512,513,514,515,523,548,554,992,993,995,1080,1125,1159,1352,1433,1494,1521,1522,1523,1524,1525,1526,1761,1993,2000,2001,2010,2049,2100,2103,3000,3268,3306,3389,3527,3632,3690,4001,4105,4848,5010,5040,5060,5432,5544,5555,5566,5631,5632,5800,5900,5985,6000,6001,6050,6070,6101,6106,6112,6129,8000,8008,8009,8080,8085,8088,8090,8105,8109,8180,8222,8333,8443,8470,8471,8472,8473,8474,8475,8476,8480,8888,9001,9084,9087,9100,9470,9471,9472,9473,9474,9475,9476,9480,9999,10000,10202,10203,20031,41523,41524"
        type = "light"
    elif portnum == "2":
        ports = "1-3,5,7,9,11,13,15,17-25,27,29,31,33,35,37-39,41-223,242-246,256-265,280-282,309,311,318,322-325,344-351,363,369-581,587,592-593,598,600,606-620,624,627,631,633-637,666-674,700,704-705,707,709-711,729-731,740-742,744,747-754,758-765,767,769-777,780-783,786,799-801,860,873,886-888,900-901,911,950,954-955,990-993,995-1001,1008,1010-1011,1015,1023-1100,1109-1112,1114,1123,1155,1167,1170,1207,1212,1214,1220-1222,1234-1236,1241,1243,1245,1248,1269,1313-1314,1337,1344-1625,1636-1774,1776-1815,1818-1824,1900-1909,1911-1920,1944-1951,1973,1981,1985-2028,2030,2032-2036,2038,2040-2049,2053,2065,2067,2080,2097,2100,2102-2107,2109,2111,2115,2120,2140,2160-2161,2201-2202,2213,2221-2223,2232-2239,2241,2260,2279-2288,2297,2301,2307,2334,2339,2345,2381,2389,2391,2393-2394,2399,2401,2433,2447,2500-2501,2532,2544,2564-2565,2583,2592,2600-2605,2626-2627,2638-2639,2690,2700-2702,2716,2766,2784-2789,2801,2908-2912,2953-2954,2967,2998,3000-3002,3006-3007,3010-3011,3020,3047-3049,3080,3127-3128,3141-3145,3180-3181,3205,3232,3260,3264,3267-3269,3279,3306,3322-3325,3333,3340,3351-3352,3355,3372,3389,3421,3454-3457,3689-3690,3700,3791,3900,3984-3986,4000-4002,4008-4009,4080,4092,4100,4103,4105,4107,4132-4134,4144,4242,4321,4333,4343,4443-4454,4500-4501,4567,4590,4626,4651,4660-4663,4672,4899,4903,4950,5000-5005,5009-5011,5020-5021,5031,5050,5053,5080,5100-5101,5145,5150,5190-5193,5222,5236,5300-5305,5321,5400-5402,5432,5510,5520-5521,5530,5540,5550,5554-5558,5569,5599-5601,5631-5632,5634,5650,5678-5679,5713-5717,5729,5742,5745,5755,5757,5766-5767,5800-5802,5900-5902,5977-5979,5997-6053,6080,6103,6110-6112,6123,6129,6141-6149,6253,6346,6387,6389,6400,6455-6456,6499-6500,6515,6543,6558,6588,6660-6670,6672-6673,6699,6767,6771,6776,6789,6831,6883,6912,6939,6969-6970,7000-7021,7070,7080,7099-7100,7121,7161,7174,7200-7201,7300-7301,7306-7308,7395,7426-7431,7491,7511,7777-7778,7781,7789,7895,7938,7999-8020,8023,8032,8039,8080-8082,8090,8100,8181,8192,8200,8383,8403,8443,8450,8484,8732,8765,8886-8894,8910,9000-9002,9005,9043,9080,9090,9098-9100,9400,9443,9495,9535,9570,9872-9876,9878,9889,10005,10007,10080-10082,10101,10202,10204,10520,10607,10666,11000-11002,11004,11223,12000-12002,12076,12223,12287,12345-12346,12361-12362,12456,12468-12469,12631,12701,12753,13000,13333,14237-14238,15858,16384,16660,16959,16969,17000,17007,17300,18000,18181-18186,18190-18192,18194,18209-18210,18231-18232,18264,19541,20000-20001,20011,20034,20200,20203,20331,21544,21554,21845-21849,22222,22273,22289,22305,22321,22555,22800,22951,23456,23476-23477,25000-25009,25252,25793,25867,26000,26208,26274,26409,27000-27009,27374,27665,29369,29891,30029,30100-30102,30129,30303,30999,31336-31337,31339,31554,31666,31785,31787-31788,32000,32768-32790,33333,33567-33568,33911,34324,37651,40412,40421-40423,42424,44337,47557,47806,47808,49400,50505,50766,51102,51107,51112,53001,54320-54321,57341,60008,61439,61466,62078,65000,65301,65512"
        type = "moderate"
    else:
        ports = "0-65535"
        type = "full"

    ip_address = ip_address.strip()

    print("INFO: Running "+type+" TCP/UDP nmap scans for " + ip_address)
    TCPSCAN = "nmap -vvv -Pn -A --open -sS -T 4 -p "+ports+" -oA discovery%snmap%stcp_%s %s"  % (sep, sep, ip_address, ip_address)
    UDPSCAN = "nmap -vvv -Pn -A --open -sU -T 4 --top-ports 200 -oA discovery%snmap%sudp_%s %s" % (sep, sep, ip_address, ip_address)

    if TCP == True:
        subprocess.check_output(TCPSCAN, shell=True, stderr=subprocess.STDOUT)
        fo = open("discovery"+sep+"nmap"+sep+"tcp_"+ip_address+".csv", 'w+')
        serviceDict = nmapparser.process("discovery"+sep+"nmap"+sep+"tcp_"+ip_address+".xml", fo)
        
    if UDP == True:
        subprocess.check_output(UDPSCAN, shell=True, stderr=subprocess.STDOUT)
        fo = open("discovery"+sep+"nmap"+sep+"udp_"+ip_address+".csv", 'w+')
        serviceDict.update(nmapparser.process("discovery"+sep+"nmap"+sep+"udp_"+ip_address+".xml", fo))

    print("INFO: TCP/UDP Nmap scans completed for " + ip_address)
    return serviceDict

print("############################################################")
print("####          Port Scanner and Service Enumerator       ####")
print("####            A multi-process service scanner         ####")
print("####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####")
print("############################################################")

if __name__=='__main__':
    main(sys.argv)
