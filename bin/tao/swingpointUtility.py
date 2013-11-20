import MySQLdb, MySQLdb.cursors
## Function used to balance source and target and load visual
def balance(source,target):
		visual = {}
		## Loads visualization for balanced graph
		if source[len(source)]['depth'] == target[len(target)]['depth']:
			for i in range(1, len(source)+1):
				if(not(source[i] in visual.itervalues())):
					visual[len(visual)+1] = source[i]
				if(not(target[i] in visual.itervalues())):
					visual[len(visual)+1] = target[i]
		## Loads visualization for unbalanced graph towards source and adjusts for the depth difference
		if source[len(source)]['depth'] > target[len(target)]['depth']:
			diff = source[len(source)]['depth'] - target[len(target)]['depth']
			for i in range(1, len(source)+1):
				if(not(source[i] in visual.itervalues())):
					visual[len(visual)+1] = source[i]
				if(not(i > len(target))) and (not(target[i] in visual.itervalues())):
					target[i]['depth'] += diff
					visual[len(visual)+1] = target[i]
		## Loads visualization for unbalanced graph towards target and adjusts for the depth difference
		if source[len(source)]['depth'] < target[len(target)]['depth']:
			diff = target[len(target)]['depth'] - source[len(source)]['depth']
			for i in range(1, len(target)+1):
				if(not(target[i] in visual.itervalues())):
					visual[len(visual)+1] = target[i]
				if(not(i > len(source))) and (not(source[i] in visual.itervalues())):
					source[i]['depth'] += diff
					visual[len(visual)+1] = source[i]
		return source,target,visual

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
	except MySQLdb.Error, e:
		print "Error %d: %s" % (e.args[0], e.args[1])
		sys.exit(1)
		
	index = 1
	parent = {}
	while not(node[index]['aki'] == None):
		## Finds all certificates with ski that matches the current certificates aki
		cur.execute("""
			SELECT * FROM rpki_cert WHERE ski=%s AND DATE(valto) > DATE(NOW()) ORDER BY DATE(valto) DESC""", (node[index]['aki']))
		## Processes each certificate one at a time as there may be one or more matches
		nodeq = cur.fetchone()
		while nodeq:
			## Creates a Dictionary for each certificate
			parent = {'filename': nodeq['filename'], 'ski': nodeq['ski'], 'aki': nodeq['aki'], 'local_id': nodeq['local_id'], 'subject': nodeq['subject']}
			## Creates a depth field for each certificate that is one greater than its child
			parent['depth'] = node[index]['depth']+1
			if(not(parent in node.itervalues())):
				node[len(node)+1] = parent
			nodeq = cur.fetchone()			
		index += 1

	return node
