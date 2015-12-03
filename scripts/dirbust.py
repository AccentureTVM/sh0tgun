#!/usr/bin/python

import sys
import os
import subprocess

def main(args):
	if len(args) < 4 :
		print("Usage: dirbust.py <target url> <root folder>")
		return

	url = str(args[1])
	root = args[2]
	ssl = args[3]
	if ssl == True:
		ssl = "https://"
	else:
		ssl = "http://"
	folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]

	found = []
	print("INFO: Starting dirb scan for " + url)
	for folder in folders:
		for filename in os.listdir(folder):

			outfile = " -o " + root + "discovery/dirb/" + url + "_dirb_" + filename
			DIRBSCAN = "dirb %s%s %s/%s %s -S -r" % (ssl,url, folder, filename, outfile)
			try:
				results = subprocess.check_output(DIRBSCAN, shell=True)
				results = results.decode('utf-8')
				resultarr = results.split("\n")
				for line in resultarr:
					if "+" in line:
						if line not in found:
							found.append(line)
			except:
				print ("ERROR: Dirbscan failed for " + url)

	if found[0] != "":
			print("[*] Dirb found the following items...")
			for item in found:
				print("   " + item)
	else:
		print("INFO: No items found during dirb scan of " + url)


if __name__=='__main__':
	main(sys.argv)