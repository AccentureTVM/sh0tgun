#!/usr/bin/env python

import sys
import os
import pickle

def main(args):
	inputfile = ""
	while not os.path.isfile(inputfile):
		inputfile = input("Enter csv file >> ")
	serviceDict = {}
	fi = open(inputfile, 'r')
	for line in fi:
		if line[0] != "i":
			line = line.split(',')
			ip = line[0]
			service = line[4]
			port = line[2]
			if service in serviceDict:
				serviceDict[service].append([ip,port])
			else:
				serviceDict[service] = []
				serviceDict[service].append([ip,port])
	
	outputfile = input ("Where would you like to save this file >> ")
	while os.path.isfile(outputfile) or not os.path.exists(outputfile):
		print("Error this is not a valid directory")
		outputfile = input ("Where would you like to save this file >> ")
	if outputfile[-1] != "/":
		outputfile = outputfile + "/"
	with open(outputfile + "serviceDict.dat","wb") as f:
		pickle.dump(serviceDict, f)
		
if __name__=='__main__':
	main(sys.argv)