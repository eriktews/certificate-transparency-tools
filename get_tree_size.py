#!/usr/bin/env python
import urllib2
import json
import argparse
from download_all_certs import *


def main():
	parser = argparse.ArgumentParser(description='Get the tree_size of a certificate transparency server')
	parser.add_argument('u', type=str, metavar='url', help='URL of the ct server, for example https://ct1.digicert-ct.com/log')
	args = parser.parse_args()
	print get_tree_size(args.u)

if __name__ == "__main__":
    main()

