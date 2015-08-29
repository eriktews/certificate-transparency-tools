#!/usr/bin/env python

import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

def get_subject(f):
	""" extract the common names (subject and subject alternative name
	from a certificate 
	"""
	c = x509.load_der_x509_certificate(f.read(),default_backend()) 
	res = []
	cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
	for i in cn:
		t = i.value
		# Common name is sometimes not a hostname, remove all that
		# contain a whitespace
		if (" " not in t):
			res.append(t) 
	try:
		# Get the Subject Alternative Name extension
		ext = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
		return res + ext.value.get_values_for_type(x509.DNSName)
	except:
		pass 
	return res


def main():
        parser = argparse.ArgumentParser(description='print the cn of a certificate')
	parser.add_argument('f', type=file, nargs="+", metavar='filename', help='DER encoded certificate file(s)')
	args = parser.parse_args()
	for i in args.f:
		try:
			for i in get_subject(i):
				print i
		except:
			pass

if __name__ == "__main__":
    main()

