This readme file pertains to the reconscan.py script and all associated scripts. 

Currently these scripts include: 
reconscan.py (main)
dirbust.py  
dnsrecon.py  
ftprecon.py  
reconscan.py  
smbrecon.py  
smtprecon.py  
snmprecon.py  
sshrecon.py
medusa.py

This collection of scripts is intended to be executed remotely against a list of IPs to enumerate discovered 
services such as smb, smtp, snmp, ftp and other.

Author: 
Tucker Pettis

How to use:
reconscan.py is the main script which calls all other scripts. Simply run it and it should do the work for you.

-i 1/2/3 for nmap scan intensity light/medium/full
-c use medusa to crack passwords for discovered services
-m use metasploit to attack (not yet implemented)
-p number of concurrent process to run (default = 4)

in order to use medusa username and password files need to be located at
    /root/wordlists/admin_usernames.txt and /root/wordlists/rockyou.txt

directory structure will be created from where script is run
targets.txt needs to be in directory where script will be run
    1 ip or range per line, no commas
