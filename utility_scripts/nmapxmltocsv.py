#!/usr/bin/python

import logging
import sys
import argparse
import xml.etree.ElementTree as ET
from subprocess import call


def main(argv):
	inputfile = ''
	outputfile = ''
	parser = argparse.ArgumentParser(description="Parse Nmap XML output and create CSV")
	parser.add_argument('inputfile', help='The XML File')
	parser.add_argument('outputfile', help='The output csv filename')
	parser.add_argument('-n', '--noheaders', action='store_true',
						help='This flag removes the header from the CSV output File')
	parser.add_argument('-a', '--allcsv', action='store_true',
						help='This flag will process all files named in inputfile and put to one output')
	args = parser.parse_args()

	inputfile = args.inputfile
	outputfile = args.outputfile
	fo = open(outputfile, 'w+')

	if (args.noheaders != True):
		out = "ip" + ',' + "hostname" + ',' + "port" + ',' + "protocol" + ',' + "service" + ',' + "version" + '\n'
		fo.write(out)

	if (args.allcsv == True):
		fi = open(inputfile, 'r')
		for inputfile in fi:
			process(inputfile.strip(), fo)
	else:
		process(inputfile, fo)

	fo.close()


def process(inputfile, fo):
	serviceDict = {}
	try:
		tree = ET.parse(inputfile)
		root = tree.getroot()

		for host in root.findall('host'):
			ip = host.find('address').get('addr')
			hostname = ""
			if host.find('hostnames') is not None:
				if host.find('hostnames').find('hostname') is not None:
					hostname = host.find('hostnames').find('hostname').get('name')
			if host.find('ports') is not None:
				for port in host.find('ports').findall('port'):
					protocol = port.get('protocol')
					if protocol is None:
						protocol = ""
					portnum = port.get('portid')
					if portnum is None:
						portnum = ""
					service = ""
					if port.find('service') is not None:
						if port.find('service').get('name') is not None:
							service = port.find('service').get('name')

					if service in serviceDict:
						serviceDict[service].append([ip,portnum])
					else:
						serviceDict[service] = []
						serviceDict[service].append([ip,portnum])
			
					product = ""
					version = ""
					versioning = ""
					extrainfo = ""
					if port.find('service') is not None:
						if port.find('service').get('product') is not None:
							product = port.find('service').get('product')
							versioning = product.replace(",", "")
						if port.find('service').get('version') is not None:
							version = port.find('service').get('version')
							versioning = versioning + ' (' + version + ')'
						if port.find('service').get('extrainfo') is not None:
							extrainfo = port.find('service').get('extrainfo')
							versioning = versioning + ' (' + extrainfo + ')'
					out = ip + ',' + hostname + ',' + portnum + ',' + protocol + ',' + service + ',' + versioning + '\n'
					fo.write(out)
			else:
				logging.warning("No open ports on " + ip)
				fo.write(ip + ",,no open ports")
				
	except ET.ParseError as e:
		print("Parse error on file " +inputfile + "  Check for proper XML formatting")
	except IOError as e:
		print("IO error on file " +inputfile + "Check for correct file name")
	except:
		print("Unexpected error on file: " + inputfile)

	return serviceDict


if __name__ == "__main__":
	main(sys.argv)
