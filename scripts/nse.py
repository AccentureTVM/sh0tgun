#!/usr/bin/env python
import subprocess
import sys

def Daytime(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=daytime --host-timeout 5m --min-hostgroup 100 " + str(ip) 
	return SCAN
	
def http(ip, port):
	SCAN = "nmap -Pn -n --open -p "+ port + " --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt " + str(ip)
	return SCAN

def FTP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def SSH(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=sshv1,ssh2-enum-algos --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Telnet(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=banner,telnet-encryption --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def SMTP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + ",465,587 --script=banner,smtp-commands,smtp-open-relay,smtp-strangeport,smtp-enum-users --script-args smtp-enum-users.methods={EXPN,RCPT,VRFY} --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Time(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=rfc868-time --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def DNS(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=dns-blacklist,dns-cache-snoop,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zeustracker,dns-zone-transfer --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def DHCP(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=dhcp-discover --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Gopher(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=gopher-ls --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def nger(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=nger --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def POP3(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=banner,pop3-capabilities --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def NFS(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def NTP(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=ntp-monlist --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def NetBIOS(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=nbstat --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def MS08_067(ip, port):
	 SCAN = "nmap  -Pn -n --open -p "+ port + " --script=smb-check-vulns --script-args=unsafe=1 --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	 return SCAN
	 
def IMAP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=imap-capabilities --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def SNMP(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=snmp-hh3c-logins,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def LDAP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=ldap-rootdse --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def SMB(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=msrpc-enum,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-server-stats,smb-system-info,smbv2-enabled,stuxnet-detect --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Ike(ip, port):
	SCAN = "nmap  -Pn -n -sS -sU --open -p "+ port + " --script=ike-version --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def DB2(ip, port):
	SCAN = "nmap  -Pn -n -sS -sU --open -p "+ port + " --script=db2-das-info,db2-discover --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Novell_NetWare_Core_Protocol(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=ncp-enum-users,ncp-serverinfo --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def AFP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def RTSP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=rtsp-methods --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def CUPS(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=cups-info,cups-queue-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def rsync(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=rsync-list-modules --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def IMAP_S(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=banner,sslv2,imap-capabilities --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def POP3_S(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=banner,sslv2,pop3-capabilities --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def COBRA(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=giop-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def SOCKS(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=socks-auth-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def RMI_Registry(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=rmi-dumpregistry --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def ICAP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=icap-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Lotus_Domino(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=domino-enum-users --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def MS_SQL(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def MS_SQL_UDP(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=ms-sql-dac --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Oracle(ip, port):
	SCAN = "nmap  --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Citrix(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=citrix-enum-apps,citrix-enum-servers --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def PPTP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=pptp-version --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def ACARS(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=acarsd-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Freelancer(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=freelancer-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def DICT(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=dict-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def GPS(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=gpsd-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Apple_Remote_Event(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=eppc-enum-processes --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def iSCSI(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=iscsi-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def MySQL(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Remote_Desktop(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=rdp-vuln-ms12-020,rdp-enum-encryption --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN
	
def STUN(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=stun-version --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Distributed_Compiler_Daemon(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=distcc-cve2004-2687 --script-args=distcc-exec.cmd='id' --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN
def Erlang_Port_Mapper(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=epmd-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Versant(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=versant-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def SIP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=sip-enum-users,sip-methods --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def DNS_Service_Discovery(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=dns-service-discovery --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Nagios(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=nrpe-enum --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def AMQP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=amqp-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def OpenLookup(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=openlookup-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def VNC(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=realvnc-auth-bypass,vnc-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def CouchDB(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=couchdb-databases,couchdb-stats --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def X11(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + "-6005 --script=x11-access --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Redis(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=redis-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Sun_Service(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=servicetags --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Voldemort(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=voldemort-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Max_DB(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=maxdb-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Hard_Disk(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=hddtemp-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def QNX_QCONN(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=qconn-exec --script-args=qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd=uname -a --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def AJP(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=ajp-methods,ajp-request --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def McAfee_ePO(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=mcafee-epo-agent --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def CouchBase_Web_Administration(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=membase-http-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Bitcoin(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + ",8333 --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Lexmark(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=lexmark-cong --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Cassandra(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=cassandra-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Java_Debug_Wire_Protocol(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=jdwp-version --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Network_Data_Management(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=ndmp-fs-info,ndmp-version --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Memory_Object_Caching(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=memcached-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def CCcam(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=cccam-version --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def NetBus(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=netbus-auth-bypass,netbus-version --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def VxWorks(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=wdb-version --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def GKRellM(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=gkrellm-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def MongoDB(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=mongodb-databases,mongodb-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def BackOrice(ip, port):
	SCAN = "nmap  -Pn -n -sU --open -p "+ port + " --script=backorice-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Flume(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=flume-master-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def DRDA(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + " --script=drda-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Hadoop(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + ",50060,50070,50075,50090 --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   
	return SCAN

def Apache_HBase(ip, port):
	SCAN = "nmap  -Pn -n --open -p "+ port + ",60030 --script=hbase-master-info,hbase-region-info --host-timeout 5m --min-hostgroup 100 " + str(ip)   

