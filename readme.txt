This readme file pertains to the sh0tgun.py script and all associated scripts. 

Currently these scripts include: 
sh0tgun.py (main)
dirbust.py  
dnsrecon.py  
ftprecon.py  
reconscan.py  
smbrecon.py  
smtprecon.py  
snmprecon.py  
sshrecon.py
medusa.py
nse.py

This collection of scripts is intended to be executed remotely against a list of IPs to enumerate discovered 
services such as smb, smtp, snmp, ftp and other.

Author: 
Tucker Pettis

How to use:
sh0tgun.py is the main script which calls all other scripts. Simply run it and it should do the work for you.

Python Version 3.1 or higher is required

Options:

-v 1/2/3 for verbosity: silent/Findings and Errors/Verbose
-p maximum number of concurrent processes to run
-r full path to location of project directory (all scan results will be placed here)

