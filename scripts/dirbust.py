#!/usr/bin/python

import sys
import os
import subprocess
import logging

def main(args):
	if len(args) < 4 :
		logging.error("Usage: dirbust.py <target url> <root folder>")
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
	logging.info("Starting dirb scan for " + url)
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
				logging.error ("Dirbscan failed for " + url)

	if found[0] != "":
			logging.info("Dirb found the following items...")
			for item in found:
				logging.info("   " + item)
	else:
		logging.info("No items found during dirb scan of " + url)


if __name__=='__main__':
	main(sys.argv)