#!/usr/bin/env python

import argparse
import sys
import json

from download_all_certs import dump_to_files

def main():
	parser = argparse.ArgumentParser(description='Parse JSON encoded CT database')
	parser.add_argument('i', type=file, metavar='input', help='filename of the input file')
	parser.add_argument('p', type=str, metavar="output-previx", help='prefix for the putput files')
	parser.add_argument('-s', type=int, metavar='startindex', help='start index for the output (default = 1)', default="1")
	args = parser.parse_args()
	try:
		j = json.load(args.i)
	except:
		# Happens for malformed JSON data
		print "Unexpected error in file " + str(args.i) + ": ", sys.exc_info()[0]
		raise
	args.i.close()
	dump_to_files(j, args.p, args.s)

if __name__ == "__main__":
    main()

