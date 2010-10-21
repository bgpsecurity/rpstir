# * ***** BEGIN LICENSE BLOCK *****
# *
# * BBN Address and AS Number PKI Database/repository software
# * Version 3.0-beta
# *
# * US government users are permitted unrestricted rights as
# * defined in the FAR.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT
# * WARRANTY OF ANY KIND, either express or implied.
# *
# * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# *
# * Contributor(s):  Ryan Caloras (rcaloras@bbn.com)
# * Date: 10/21/2010
# *
# * ***** END LICENSE BLOCK ***** */

from datetime import datetime
from time import time

class Factory:
	def __init__(self, bluePrintName = "", ipv4List = [], ipv6List= [],\
			asList = [], childSpec = [()], serverName = "", breakAway = False, ttl = 0):
		# Particular type of CA object as specified in config file
		self.bluePrintName = bluePrintName
		
		self.ipv4List = ipv4List
		self.ipv6List = ipv6List
		
		#Autonomous system list
		self.asList = asList
		
		#Specification of children that reside under this CA as a list
		#of tuples. [(bluePrintName, amount),..]
		self.childSpec = childSpec
		
		self.serverName = serverName
		
		self.breakAway = breakAway
		
		#Time to live given as seconds due
		self.ttl = ttl
		
	def create(self, parent):
		print "creating a CA_object as specified by "+ self.bluePrintName
		#return CA_object(parent,self)
		
	


class CA_Object:
	def __init__(self, parent, myFactory):
		self.nextChildSN = 0
		self.id = parent.getNextChildSN()
		self.myFactory = myFactory
		self.bluePrintName = myFactory.bluePrintName
		self.parent = parent
		self.notBefore = datetime.now()
		self.notAfter = datetime.fromtimestamp(time()+myfactory.ttl)
		
		#List initialization
		self.children = []
		self.manifests = []
		self.roas = []
		self.crl = []
		
		#self.keys = generateKeys()
		try:
			pass
			#self.ipResourcesOwned = parent.allocate(..)
			#self.asResourcesOwned = parent.allocate(...as)
		except:
			print "Error occured in allocating resources for this CA_object"

		#self.ipResourcesFree = self.ipResourcesOwned
		#self.asResourcesOwned = self.asResourcesOwned
		#self.AIA = parent.rsync_URI_CA_CERT
		#self.CRLDP = parent.rsynch_URI_CRLDP
		if factory.breakAway:
			pass
			#self.SIA = myFactory.serverName + "/"+ commonName
		else:
			pass
			#self.SIA = parent.SIA + "/" + commonName

		#self.certificate = CA_Cert(...)
		#self.path_CA_CERT = parent.SIA+"/"+myfilename
		#self.path_URI_CRLDP =
		
	def allocate(self):
		pass
		
	def getNextChildSN(self):
		nextChild = nextChildSN
		nextChildSN += 1
		return nextChild
		
		
