#!/usr/bin/env python
import subprocess
import sys
import os

def main(args):
    if len(args) != 3:
        print("Usage: ftprecon.py <ip address> <port>")
        return

    ip_address = args[1].strip()
    port = args[2].strip()
    print("INFO: Performing nmap FTP script scan for " + ip_address + ":" + port)
    FTPSCAN = "nmap -sV -Pn -vv -p %s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN 'discovery/ftp/%s_ftp.nmap' %s" % (port, ip_address, ip_address)
    results = subprocess.check_output(FTPSCAN, shell=True)
    outfile = "discovery/ftp/" + ip_address + "_ftprecon.txt"
    f = open(outfile, "w")
    f.write(results)
    f.close

if __name__=='__main__':
    main(sys.argv)