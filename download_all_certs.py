#!/usr/bin/env python
import urllib2
import json
import argparse
import sys
import base64
from os.path import isfile
from struct import unpack


def read_int24(d, idx):
        """ Read a 3 byte integer as used by TLS or Certificate Transparency
        """
        return unpack(">I", '\x00' + d[idx:idx+3])[0]

def read_int16(d, idx):
	""" Read a 2 byte integer
	"""
	return unpack(">H", d[idx:idx+2])[0]

def dump_to_files(json_data, prefix, counter):
        """ Dump json CT encoded certificates (extra_data) into seperate files
        """
        for k in json_data['entries']:
		leaf_input = base64.b64decode(k['leaf_input'])
		logEntryType = read_int16(leaf_input, 10)
		print "Type of " + str(counter) + " is " + str(logEntryType)
		# only look for x509 certificates, no precertificates.
		if (logEntryType == 0):
			
	                # Open the output file
	                o = open(filename(prefix, counter), 'w')
			l = read_int24(leaf_input, 12)
	                # Extract the certificate and write it to the file
			cert = leaf_input[15:l+15]
	                o.write(cert)
	                o.close()
			# The remaining contents of leaf_input are skipped,
			# they contain the chain for verification.
		counter = counter + 1 
	return len(json_data['entries'])

def get_tree_size(url):
	""" Get the current tree size of a CT server
	"""
        j = json.loads(urllib2.urlopen(url + "/ct/v1/get-sth").read())
        return j['tree_size']

def filename(prefix, i):
	""" Filename of a file with prefix and counter
	"""
	return prefix + str(i) + ".der"

def next_missing_index(prefix, i):
	""" Determine netxt index that has not yet been downloaded
	"""
	while(isfile(filename(prefix, i))):
		i = i+1
	return i

def first_missing(prefix, max):
	for j in xrange(max, 0, -1):
		if (isfile(filename(prefix, j))):
			return j+1
	return 0

def check_missing(prefix, i, limit):
	""" Determine how many files we need to download
	"""
	while((not isfile(filename(prefix, i))) and (i < limit)):
		i = i+1
	return i

def download_json_certs(url, start, end):
	""" Retrieve JSON encoded certs from a CT server
	"""
	return json.loads(urllib2.urlopen(url + "/ct/v1/get-entries?start=" + str(start) + "&end=" + str(end)).read())

def download_all_certs(url, prefix):
	""" Download all certs from a CT server
	"""
	size = get_tree_size(url)
	print "size is", size
	i = first_missing(prefix, size)
	while(i < size):
		r = i+63
		print "downloading", i, r
		i = i + dump_to_files(download_json_certs(url, i, r), prefix, i)


def main():
	parser = argparse.ArgumentParser(description='Retrieve and dump all certificates from a CT server')
	parser.add_argument('u', type=str, metavar='url', help='URL of the CT server')
	parser.add_argument('p', type=str, metavar="output-previx", help='prefix for the putput files')
	args = parser.parse_args()
	download_all_certs(args.u, args.p)

if __name__ == "__main__":
    main()

