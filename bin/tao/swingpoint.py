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
def swingpoint(src, tar):
	import utility as util
	result = []

	src = src.strip()
	tar = tar.strip()
	source = {} # source dictionary
	target = {} # target dictionary
	visual = {} # visualization dictionary
	intersection = {} #intersection dictionary

	index = 1
	depth = 1
	output = ""
	lowest = sys.maxint

	try:
		## Establish Connection to RPSTIR Database
		con = MySQLdb.connect(
			host='localhost', 
			user='rpstir', 
			passwd='bbn', 
			db='rpstir_test', 
			# use the cursor class DictCursor to return a dictionary result instead of a tuple for queries
			cursorclass=MySQLdb.cursors.DictCursor
		)
		cur = con.cursor()

		if options.certificate:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE filename=%s AND DATE(valto) > DATE(NOW()) ORDER BY DATE(valto) DESC""", (src))

		if options.ski:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE ski=%s AND DATE(valto) > DATE(NOW()) ORDER BY DATE(valto) DESC""", (src))
		srcq = cur.fetchone()
		if options.certificate:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE filename=%s AND DATE(valto) > DATE(NOW()) ORDER BY DATE(valto) DESC""", (tar))

		if options.ski:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE ski=%s AND DATE(valto) > DATE(NOW()) ORDER BY DATE(valto) DESC""", (tar))
		targetq = cur.fetchone()

		try:
			## Handle Source Query Results
			if srcq is None:
				raise Exception("No row found for source \'%s\'" % src)
			else:
				sski = srcq['ski']
				saki = srcq['aki']
			## Handle Target Query Results
			if targetq is None: 
				raise Exception("No row found for target \'%s\'" % tar)
			else:
				tski = targetq['ski']
				taki = targetq['aki']
		except Exception , err:
			sys.stderr.write('ERROR: %s\n' % str(err))
			sys.exit()

		## Handle Edge Case(Source is Targets Parent and Vice Versa)
		if(sski == taki): 
			return '*'+srcq['filename']+'\n'+targetq['filename']+'\nSwingpoints: ['+srcq['filename']+']'
		if(saki == tski): 
			return '*'+targetq['filename']+'\n'+srcq['filename']+'\n'+'Swingpoints: ['+targetq['filename']+']'

		src = {'filename': srcq['filename'], 'ski': srcq['ski'], 'aki': srcq['aki']}
		tar = {'filename': targetq['filename'], 'ski': targetq['ski'], 'aki': targetq['aki']}
		
		## Load source and target into the first entry and set depth
		source[index] = src
		source[index]['depth'] = 0
		target[index] = tar
		target[index]['depth'] = 0

		## Throw exception on bad source or target certificates
		try:
			if (source[index]['aki'] == None) and (target[index]['aki'] == None):
				raise Exception("Source and Target do not have valid authority key identifier")
		except Exception , err:
			sys.stderr.write('ERROR: %s\n' % str(err))
			sys.exit()
	
		## Loads the Source Dictionary
		source = util.findParents(source)
		## Loads the Target Dictionary
		target = util.findParents(target)

		## Calls Utility function Balance to adjust depths and load visual
		source,target,visual = util.balance(source,target)

		## Finds the intersection of source and target dictionaries
		intersection = util.intersection(source,target)

		## Finds the lowest point certificate in the intersection
		for i in range(1,len(intersection)+1):
			if intersection[i]['depth'] <= lowest:
				lowest = intersection[i]['depth']
				result.append(intersection[i]['filename'])

		## Displays visualization based on Depth
		depth = visual[len(visual)]['depth']
		for x in range(depth,-1,-1):
			for i in range(1,len(visual)+1):
				## Prepends the swingpoints with a *
				if x == lowest:
					prepend = "*"
				else:
					prepend = " "
				if visual[i]['depth'] == x:
					output = output + prepend + visual[i]['filename'] + " "
			print output
			output = ""

		return "Swingpoints: %s" % result

	except MySQLdb.Error, e:
		print "Error %d: %s" % (e.args[0], e.args[1])
		sys.exit(1)

	finally:
		if con:
			con.close()

if args and len(args) > 1:
	print swingpoint(args[0], args[1])
else:
	## Handle Invalid Source and/or Target inputs
	try:
		raise ValueError("Invalid source and/or target identifier. See \'--help\' for usage information.")
	except Exception, err:
		sys.stderr.write('ERROR: %s\n' % str(err))
