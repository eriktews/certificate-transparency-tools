#!/usr/bin/env python

import argparse
from OpenSSL import crypto

def get_subject(f):
	""" extract the common name from a certificate
	"""
	c = crypto.load_certificate(crypto.FILETYPE_DER, f.read())
	s = c.get_subject()
	for [a,b] in s.get_components():
		if (a == 'CN'):
			return b
	return ""

def main():
        parser = argparse.ArgumentParser(description='print the cn of a certificate')
	parser.add_argument('f', type=file, metavar='filename', help='DER encoded certificate file')
	args = parser.parse_args()
	print get_subject(args.f)

if __name__ == "__main__":
    main()

