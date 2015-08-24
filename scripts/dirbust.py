#!/usr/bin/python

import sys
import os
import subprocess

def main(args):
	if len(args) < 2 :
		print("Usage: dirbust.py <target url>")
		sys.exit(0)

	url = str(args[1])
	folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]

	found = []
	print("INFO: Starting dirb scan for " + url)
	for folder in folders:
		for filename in os.listdir(folder):

			outfile = " -o " + "discovery/dirb/" + url + "_dirb_" + filename
			DIRBSCAN = "dirb %s %s/%s %s -S -r" % (url, folder, filename, outfile)
			try:
				results = subprocess.check_output(DIRBSCAN, shell=True)
				resultarr = results.split("\n")
				for line in resultarr:
					if "+" in line:
						if line not in found:
							found.append(line)
			except:
				pass

	try:
		if found[0] != "":
			print("[*] Dirb found the following items...")
			for item in found:
				print("   " + item)
	except:
		print("INFO: No items found during dirb scan of " + url)


if __name__=='__main__':
	main(sys.argv)