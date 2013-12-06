import MySQLdb, MySQLdb.cursors
## Function used to balance source and target and load visual
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

## Function used to find the intersection of Source and Target dictionaries
def intersection(source,target):
	results = {}
	## Loop through both lists and check for matches
	for i in range(1, len(source)+1):
		if source[i] in target.itervalues():
			results[len(results)+1] = source[i]
	return results

## Loads a dictionary with all nodes above the given node
def findParents(node):
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

def visualize(options, lowest, node):
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

		for x in range(len(node), 0, -1):
			prepend = str(node[x]['depth'])
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
					uri = dirq['dirname'].split(rootq['rootdir'])[-1].split('/')[0]
					print "\tURI Path: rsync://" + uri
				
			if options.subject:
				if node[x]['ski'] and node[x]['subject']:
					print "\t(ski, subject): (" + node[x]['ski'] + " ," + node[x]['subject'] + ")"
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

def findCert(options, node):
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
