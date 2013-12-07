###
# Program: swingpointUtility.py
# Author(s): Brian Buchanan, John Slivka, Elijah Batkoski
# Description: This is the utility file for swingpoint.py and handles majority of the functions that are
# 	used mutiple times or used to provide calculations
###
import MySQLdb, MySQLdb.cursors
###
# This function is given both the source and target dictionary.  Both dictionaries are already sorted due 
# to the way they are loaded; therefore, the highest index of the dictionary will be the "lowest" in depth.
# Then the dictionaries are balance to ensure common nodes have the same depth.
###
def balance(source,target):
		## Loads visualization for unbalanced graph towards source and adjusts for the depth difference
		if source[len(source)]['depth'] > target[len(target)]['depth']:
			diff = source[len(source)]['depth'] - target[len(target)]['depth']
			for i in range(1, len(source)+1):
				if(not(i > len(target))):
					target[i]['depth'] += diff
		## Loads visualization for unbalanced graph towards target and adjusts for the depth difference
		if source[len(source)]['depth'] < target[len(target)]['depth']:
			diff = target[len(target)]['depth'] - source[len(source)]['depth']
			for i in range(1, len(target)+1):
				if(not(i > len(source))):
					source[i]['depth'] += diff
		return source,target

###
# This function is a simple intersection of both source and target dictionaries
###
def intersection(source,target):
	results = {}
	## Loop through both lists and check for matches
	for i in range(1, len(source)+1):
		if source[i] in target.itervalues():
			results[len(results)+1] = source[i]
	return results

###
# This function is given a dictionary containing one node and parses up the graph based on
# SKI/AKI pairs.  The dictionary is loaded by (index:nodeInfo).  The index is used in this function
# as a proxy for calculating depth.  The variable multiple is used to test that if multiple parents
# are found then both must have null AKIs to terminate the loop
###
def findParents(node):
	try:
		## Establish Connection to RPSTIR Database
		con = getCon()
		cur = con.cursor()

		index = 1
		multiple = 1
		parent = {}
		while not(multiple == 0) and not(node[index]['aki'] == None):
			multiple = 0			
			## Finds all certificates with ski that matches the current certificates aki
			cur.execute("""
				SELECT * FROM rpki_cert WHERE ski=%s AND DATE(valto) > DATE(NOW()) ORDER BY DATE(valto) DESC""", (node[index]['aki']))
			## Processes each certificate one at a time as there may be one or more matches
			nodeq = cur.fetchone()
			while nodeq:
				multiple += 1
				## Creates a Dictionary for each certificate
				parent = {'filename': nodeq['filename'], 'ski': nodeq['ski'], 'aki': nodeq['aki'], 'local_id': nodeq['local_id'], 'subject': nodeq['subject']}
				## Creates a depth field for each certificate that is one greater than its child
				parent['depth'] = node[index]['depth']+1
				if(not(parent in node.itervalues())):
					node[len(node)+1] = parent
				if parent['aki'] == None:
					multiple -= 1
				nodeq = cur.fetchone()
			index += 1

		return node
	except MySQLdb.Error, e:
		print "Error %d: %s" % (e.args[0], e.args[1])
		sys.exit(1)
	finally:
		if con:
			con.close()
###
# Visualize is passed in display options, the value of the lowest depth based on the intersection, and
# a dictionary of nodes from either the source or target.  Each node is printed out in a list format 
# displaying the desired information based on options.  The swingpoints are pepended with a *.
###
def visualize(options, lowest, node):
	try:
		## Establish Connection to RPSTIR Database
		con = getCon()
		cur = con.cursor()

		for x in range(len(node), 0, -1):
			prepend = str(node[x]['depth'])
			## Prepends swingpoints with a *
			if node[x]['depth'] == lowest:
				prepend = "*" + prepend
			else:
				prepend = " " + prepend
			print (prepend + ":\tFilename: " + node[x]['filename'])
			if options.uri:
				cur.execute("SELECT * FROM rpki_dir WHERE dir_id = %s", (node[x]['local_id']))
				dirq = cur.fetchone()
				cur.execute("SELECT * FROM rpki_metadata WHERE local_id = %s", node[x]['local_id'])
				rootq = cur.fetchone()
				if dirq and dirq['dirname'] and rootq and rootq['rootdir']:
					uri = dirq['dirname'].split(rootq['rootdir']+'/')[-1].split('/')[0]
					print "\tURI Path: rsync://" + uri
				
			if options.subject:
				#if node[x]['ski'] and node[x]['subject']:
				#	print "\t(ski, subject): (" + node[x]['ski'] + " ," + node[x]['subject'] + ")"
				if node[x]['subject']:
					print "\tSubject: " + node[x]['subject']
				if node[x]['ski']:
					print "\tSKI: " + str(node[x]['ski'])
			print ""
		return 1

	except MySQLdb.Error, e:
		print "Error %d: %s" % (e.args[0], e.args[1])
		sys.exit(1)
	finally:
		if con:
			con.close()
###
# This function is used to find the initial source and target certificate based on the options flag
###
def findCert(options, node):
	try:
		## Establish Connection to RPSTIR Database
		con = getCon()
		cur = con.cursor()	

		nodeq = None
		if options.certificate:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE MOD(flags,16) < 8 AND filename=%s AND DATE(valto) > DATE(NOW()) ORDER BY DATE(valto) DESC""", (node))

		if options.ski:
			cur.execute("""
				SELECT * FROM rpki_cert WHERE MOD(flags,16) < 8 AND ski=%s AND DATE(valto) > DATE(NOW()) ORDER BY DATE(valto) DESC""", (node))
		nodeq = cur.fetchone()

		return nodeq
	except MySQLdb.Error, e:
		print "Error %d: %s" % (e.args[0], e.args[1])
		sys.exit(1)
	finally:
		if con:
			con.close()

###
# Creates a connection to the rpstir test database.
###
def getCon():
	return MySQLdb.connect(
			host='localhost', 
			user='rpstir', 
			passwd='bbn', 
			db='rpstir_test', 
			# use the cursor class DictCursor to return a dictionary result instead of a tuple for queries
			cursorclass=MySQLdb.cursors.DictCursor
		)
