#!/usr/bin/python

import sys

bad_PDUs_hex = [
	'0a 0a 0a',
]

bad_PDUs = [''.join([chr(int(c, 0x10)) for c in s.split(' ')]) for s in bad_PDUs_hex]


if __name__ == '__main__':
	def print_usage():
		print("Usage: %s <index> | length" % sys.argv[0])
		print("    %s <index>: output the bad PDU at the 1-based index specified" % sys.argv[0])
		print("    %s length: output the total number of bad PDUs" % sys.argv[0])
		sys.exit(1)

	if len(sys.argv) != 2:
		print_usage()

	if sys.argv[1] == 'length':
		print len(bad_PDUs)
		sys.exit()

	try:
		index = int(sys.argv[1])
	except ValueError:
		print_usage()

	if index < 1:
		print_usage()
	if index > len(bad_PDUs):
		sys.exit("Error: index %d is greater than the total number of PDUs (%d)" % (index, len(bad_PDUs)))

	print bad_PDUs[index - 1]
