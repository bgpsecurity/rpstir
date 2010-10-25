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
	def __init__(self, allocated = false, range, ca_name, block_id= 0):
		self.allocated = allocated
		#integer tuple or netaddr.IPRange
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
		self.nickName= bluePrintName+str(id)
		self.commonName = parent.commonName+"."+nickName
		self.aki = parent.ski
		
		#List initialization
		self.children = []
		self.manifests = []
		self.roas = []
		self.crl = []

		if factory.breakAway:
			self.SIA = myFactory.serverName + "/"+nickName
		else:
			self.SIA = parent.SIA + "/" +nickName
			
		
		#Generate our keyfile by creating a parallel repository for keys
		#Keys are placed under a directory of their SIA. For example
		#IANA's key should be in IANA/IANA.p15, APNIC's, should be in something
		#like IANA/APNIC1/APNIC1.p15
		keyFileName = "objects/keys/"+SIA+"/"+nickName+".p15"
		command_string = "../cg/tools/gen_key "+keyFileName+ " 1024"
		#Execute the gen_key command
		os.system(command_string)
		
		#set our ski based on the hash of the public key in our keyfile
		self.ski = result from .p15-> hash(public_key) which is a hex string
		
		try:
			#tuple of type([ipv4 netaddrs,...], [ipv6 netaddrs,...], [as_nums(start,end),...])
			self.ResourcesOwned = parent.allocate(myFactory.ipv4List, myFactory.ipv6List, myFactory.asList)
		except:
			print "Error occured in allocating resources for this CA_object"

		self.AIA = parent.path_CA_cert
		self.CRLDP = parent.SIA+"/"+crlfileName.... computed by B64(parent.ski)
		self.path_CA_cert = parent.SIA+"/"B64(my ski)  
		
		#Parse out the resources we've been allocated to blocks and strings for our certificate
		#Create lists for our blocks for sub_allocation to child ca's.
		self.ip4ResourcesFree = []; self.ip6ResourcesFree = [] ;self.asResourcesFree = []
		ip4Strings = []; ip6Strings = []; asStrings = []
		#IPV4
		for ipRange in ResourcesOwned[0]:
			#Put the netaddr into a block and add it to our list of free resources
			self.ip4ResourcesFree.append(Resource_Block(false, ipRange, id))
			#Get the string representation of our address and add it to the list we'll pass to CA_cert
			ip4Strings.append(str(ipRange))
		#IPv6 same deal as above
		for ipRange in ResourcesOwned[1]:
			self.ip6ResourcesFree.append(Resource_Block(false, ipRange, id))
			ip6Strings.append(str(ipRange))
		#AS numbers
		for asRange in ResourcesOwned[2]:
			#Put the integer tuple into a block and add it to our list of free resources
			self.asResourcesFree.append(Resource_Block(false, asRange, id))
			#Get the string representation of our address and add it to the list we'll pass to CA_cert
			asStrings.append(str(asRange[0])+"-"str(asRange[1])))
			
			
		self.certificate = CA_Cert(parent.getNextChildSN(),parent.commonName, \
				commonName, notBefore,notAfter,aki,ski,keyFileName, \
				parent.keyFileName, ip4Strings, ip6Strings, asStrings, \
				path_CA_Cert, "rsync://"+CRLDP,"rsync://"+SIA,"rsync://"+AIA)
		
		
	def subAllocateIP4(self,iplist):
		return [netaddr.IPRange("0.0.0.0","0.0.0.255")]
	def subAllocateIP6(self,iplist):
		return [netaddr.IPRange("1::0","255::0")]
	def subAllocateAS(self, asList):
		return [(0,1)]
	
	def allocate(self, ipv4List, ipv6List, asList):
		return(suballocateIP4(ipv4List),suballocateIP6(ipv6List),suballocateAS(asList))
		
	
	def getNextChildSN(self):
		nextChild = nextChildSN
		nextChildSN += 1
		return nextChild
		
		
