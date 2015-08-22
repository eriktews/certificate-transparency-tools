#!/usr/bin/env python

import argparse
from OpenSSL import crypto

def get_subject(f):
	""" extract the common name from a certificate
	"""
	c = crypto.load_certificate(crypto.FILETYPE_ASN1, f.read())
	s = c.get_subject()
	for [a,b] in s.get_components():
		if (a == 'CN'):
			if not " " in b:
				return b
	return ""

def main():
        parser = argparse.ArgumentParser(description='print the cn of a certificate')
	parser.add_argument('f', type=file, nargs="+", metavar='filename', help='DER encoded certificate file')
	args = parser.parse_args()
	for i in args.f:
		try:
			print get_subject(i)
		except:
			pass

if __name__ == "__main__":
    main()

