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
import netaddr

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
		
class Resource_Block:
	def __init__(allocated = false, range, ca_name, block_id= 0):
		self.allocated = allocated
		#integer tuple
		self.range = range
		self.ca_name = ca_name
		#not sure if a unique identifier is needed yet
		self.block_id = block_id


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
			#tuple of type(ipv4 netaddr, ipv6 netaddr, as_nums(start,end))
			self.ResourcesOwned = parent.allocate(myFactory.ipv4List, myFactory.ipv6List, myFactory.asList)
		except:
			print "Error occured in allocating resources for this CA_object"

		#self.AIA = parent.rsync_URI_CA_CERT
		#self.CRLDP = parent.rsynch_URI_CRLDP
		if factory.breakAway:
			pass
			self.SIA = myFactory.serverName + "/"+ commonName
		else:
			pass
			self.SIA = parent.SIA + "/" + commonName

		#self.certificate = CA_Cert(...)
		#self.path_CA_CERT = parent.SIA+"/"+myfilename
		#self.path_URI_CRLDP =
		
		#Create our lists of resource blocks for sub_allocation to child ca's.
		self.ip4ResourcesFree = [Resource_Block(false, (ResourcesOwned[0].first, ResourcesOwned[0].last), id)]
		self.ip6ResourcesFree = [Resource_Block(false, (ResourcesOwned[1].first, ResourcesOwned[1].last), id)]
		self.asResourcesFree = [Resource_Block(false, ResourcesOwned[2], id)]
		
	def subAllocateIP4(self,iplist):
		return netaddr.IPRange("0.0.0.0","0.0.0.255")
	def subAllocateIP6(self,iplist):
		return netaddr.IPRange("0.0.0.0","0.0.0.255")
	def subAllocateAS(self, asList):
		pass
	
	def allocate(self, ipv4List, ipv6List, asList):
		suballocateIP4(ipv4List)
		suballocateIP6(ipv6List)
		suballocateAS(asList)
		
	
	def getNextChildSN(self):
		nextChild = nextChildSN
		nextChildSN += 1
		return nextChild
		
		
