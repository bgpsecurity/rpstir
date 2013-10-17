#!/usr/bin/python
#!@PYTHON@

# swingpoint.py
#
# Locate root authority hierarchy given a source and target
# certificate or SKI as input. Uses current RPKI database and local
# repository files.
#
# usage: swingpoint.py [options]
#
# options:
# -h, --help
# -c, --certificate
# -i, --ski

from subprocess import Popen, PIPE
import os, sys
from optparse import OptionParser
import MySQLdb, MySQLdb.cursors

#
# Command line parsing options
#

description = """\
Print a diagram of the current authority hierarchy in the RPKI cache. This helps
determine where credentials need to be both relinquished to, and from where credentials
need to be assigned. Accepts \'.cer\' certificate files as input by default. Set the \'-s\'
SKI flag to provide source key identifiers.
"""
usage = "usage: %prog [options] source target"
parser = OptionParser(description=description, usage=usage)
parser.add_option("-c", "--certificate",
				action="store_true", dest="certificate", default=True)
parser.add_option("-s", "--ski",
				action="store_true", dest="ski", default=False)

(options, args) = parser.parse_args()

#
# Return the swingpoint hierarchy
#
def swingpoint(src, target):
	# tree to store hierarchy, in case we
	# want to do other things with this later	

	src = src.strip()
	target = target.strip()

	table = {} # source SKI list

	try:
		con = MySQLdb.connect(
			host='localhost', 
			user='rpstir', 
			passwd='bbn', 
			db='rpstir', 
			# use the cursor class DictCursor to return a dictionary result instead of a tuple for queries
			cursorclass=MySQLdb.cursors.DictCursor
		)
		cur = con.cursor()

		if options.certificate:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE filename = %s""", (src,))

		if options.ski:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE ski = %s""", (src,))

		srcq = cur.fetchone()
		if srcq is None:
			# log exception
			raise Exception("No row found for source \'%s\'" % src)

		if options.certificate:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE filename = %s""", (target,))

		if options.ski:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE ski = %s""", (target,))

		targetq = cur.fetchone()
		if targetq is None: 
			# log exception
			raise Exception("No row found for target \'%s\'" % target)

		sski = srcq['ski']
		tski = targetq['ski']
		saki = srcq['aki']
		taki = targetq['aki']

		if(sski == taki): return taki
		if(saki == tski): return tski

		while 1:
			table[sski] = sski

			# sski = saki -> traverse to parent
			cur.execute("""
				SELECT * FROM rpki_cert WHERE ski = %s""", (saki,))
			srcq = cur.fetchone()

			if srcq is not None: 
				saki = srcq['aki']
				sski = srcq['ski']
			else:
				break

		while 1:
			if tski and tski in table: return tski
			
			cur.execute("""
				SELECT * FROM rpki_cert WHERE ski = %s""", (taki,))
			targetq = cur.fetchone()

			if targetq is not None:
				taki = targetq['aki']
				tski = targetq['ski']
			else:
				break

		return None
			
	except MySQLdb.Error, e:
		print "Error %d: %s" % (e.args[0], e.args[1])
		sys.exit(1)

	finally:
		if con:
			con.close()

# testing...
if args and len(args) > 1:
	print swingpoint(args[0], args[1])
else:
	print "must supply source and target identifiers."

