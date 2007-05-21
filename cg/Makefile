#
# Makefile for all asn.1 libs and tools
#
# $Id$
#

all:	casn.dir asn_gen.dir asn.dir tools.dir

casn.dir:
	cd casn && make all

asn_gen.dir:
	cd asn_gen && make all

asn.dir:
	cd asn && make all

tools.dir:
	cd tools && make all

clean:
	cd casn && make clean
	cd asn_gen && make clean
	cd asn && make clean
	cd tools && make clean
