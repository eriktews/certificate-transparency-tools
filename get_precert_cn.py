#!/usr/bin/env python

import argparse

from pyasn1_modules import rfc2459
from pyasn1.codec.der import decoder
from pyasn1_modules.rfc2459 import TBSCertificate
import pyasn1

def decode_string(valt, val):
	if valt == 'teletextString':
		val = str(val).decode('iso8859-1')
	else:
		val = str(val)
	return val
	
def get_subject(f):
	""" return a list of subjects frmo a tbsCertificate
	"""
	tbs = f.read()
	res = []

	# based on the original ct tools
	cert, rest = decoder.decode(tbs, asn1Spec=TBSCertificate())

	# First, try the CN field in the subject
	subject = cert['subject']
	l = subject.getComponent()

	for i in l:
		for attr in i:
			if attr['type'] == rfc2459.id_at_commonName:
				val, rest = decoder.decode(attr.getComponentByName('value'),asn1Spec=rfc2459.X520name())
				valt = val.getName()
				val = val.getComponent()
        			s = decode_string(valt, val)
				if (" " not in s):
					res.append(s)

	# Now, try the SubjectAlternativeName in the extensions
	try:
		# based on https://github.com/google/certificate-transparency/blob/master/cpp/client/fix-chain.py
		ext = cert['extensions']
		for i in ext:
			oid = i['extnID']
			if oid != rfc2459.id_ce_subjectAltName:
				continue
			subject_alt_names_raw = decoder.decode(i.getComponentByName('extnValue'), asn1Spec=pyasn1.type.univ.OctetString())[0] 
			subject_alt_names = decoder.decode(subject_alt_names_raw, asn1Spec=rfc2459.SubjectAltName())[0]
			for general_name in subject_alt_names:
				subject_alt_name_type = general_name.getName()
				subject_alt_name_value = general_name.getComponent()
				if (subject_alt_name_type == "dNSName"):
					res.append(str(subject_alt_name_value))
	except:
		pass
	return res

def main():
        parser = argparse.ArgumentParser(description='print the cn of a tbsCertificate')
        parser.add_argument('f', type=file, nargs="+", metavar='filename', help='DER encoded tbsCertificate structure file(s)')
        args = parser.parse_args()
        for i in args.f:
                try:
                        for i in get_subject(i):
                                print i
                except:
                        pass

if __name__ == "__main__":
    main()

