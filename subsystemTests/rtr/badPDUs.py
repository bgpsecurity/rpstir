#!/usr/bin/python

import sys


bad_PDUs_hex = [
	# generic errors
	'01 02 00 00 00 00 00 08', # invalid protocol version = 1, otherwise valid Reset Query
	'00 ff 00 00 00 00 00 08', # invalid PDU type, otherwise valid Reset Query
	'00 00 f0 0f ff ff ff ff', # length too long TODO: this should try to send 0xFFFFFFFF bytes, maybe
	# TODO: PDUs with truncated headers?

	# Serial Notify
	'00 00 f0 0f 00 00 00 08', # length too short
	'00 00 f0 0f 00 00 00 0b f0 0f f0', # length too short
	'00 00 f0 0f 00 00 00 0d f0 0f f0 0f f0', # length too long

	# Serial Query
	'00 01 f0 0f 00 00 00 08', # length too short
	'00 01 f0 0f 00 00 00 0b f0 0f f0', # length too short
	'00 01 f0 0f 00 00 00 0d f0 0f f0 0f f0', # length too long

	# Reset Query
	'00 02 00 00 00 00 00 09 f0', # length too long

	# TODO: Cache Response

	# TODO: IPv4 Prefix

	# TODO: IPv6 Prefix

	# TODO: End of Data

	# TODO: Cache Reset

	# Error Report
	'00 0a 00 01 ' + '00 00 00 11 ' + '00 00 00 00 ' + '00 00 00 00 ' + 'f0', # Internal Error with internal lengths less than total length
	'00 0a 00 01 ' + '00 00 00 10 ' + '00 00 00 00 ' + '00 00 00 01', # Internal Error with internal lengths greater than total length
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
