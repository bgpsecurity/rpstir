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
import base64
import os

#Quick import hack, linked to src/create_objects
from create_objects_ln import *

OBJECT_PATH = "./objects"
REPO_PATH = OBJECT_PATH+"/REPOSITORY"

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
	def __init__(self, range, ca_name, block_id= 0, allocated=False):
		#integer tuple or netaddr.IPRange
		self.range = range
		self.ca_name = ca_name
		#not sure if a unique identifier is needed yet
		self.block_id = block_id
		self.allocated = allocated

class CA_Object:

	def __init__(self, myFactory, parent=None):

		#If the certificate is self signed, for example IANA. Then it has no
		#parent and we must initialize its values accordingly
		if parent==None:
			self.nextChildSN = 0
			self.id = 0
			self.myFactory = myFactory
			self.bluePrintName = myFactory.bluePrintName
			self.parent=None
			self.notBefore = datetime.datetime.now()
			self.notAfter = datetime.datetime.fromtimestamp(time()+myFactory.ttl)
			self.nickName= self.bluePrintName+"-"+str(self.id)
			self.commonName = self.nickName
			#List initialization
			self.children = []
			self.manifests = []
			self.roas = []
			self.crl = []
			self.SIA = self.commonName

			self.keyFileName = OBJECT_PATH+"/keys/"+self.SIA+"/"+self.nickName+".p15"
			command_string = "../cg/tools/gen_key "+self.keyFileName+ " 1024"
			print command_string
			#Make our directory for the key and execute the gen_key command
			#Genkey doesn't create the directory if it doesn't exist.
			dir_path = OBJECT_PATH+"/keys/"+self.SIA
			if not os.path.exists(dir_path):
				os.system("mkdir -p "+ dir_path)
			os.system(command_string)
			
			self.ski = generate_ski(self.keyFileName)
			self.aki = self.ski
			#For self signed cert we directly pass the resources, no call to parent.allocate
			self.ResourcesOwned = (self.myFactory.ipv4List, self.myFactory.ipv6List, self.myFactory.asList)
			#Parse out the resources we've been allocated to blocks and strings for our certificate
			#Create lists for our blocks for sub_allocation to child ca's.
			self.ip4ResourcesFree = []; self.ip6ResourcesFree = [] ;self.asResourcesFree = []
			self.ip4Strings = []; self.ip6Strings = []; self.asStrings = []
			self.parseResources()
			#Sort of a special case, we want the top of our repository to be
			self.path_CA_cert = REPO_PATH+"/"+base64.urlsafe_b64encode(self.ski)+".cer"
			print "Got Here about to call SS_cert constructor"	
			print self.path_CA_cert
			dir_path = REPO_PATH+"/"
			if not os.path.exists(dir_path):
				os.system("mkdir -p "+ dir_path)

			self.certificate = SS_cert(self.id,self.commonName,self.commonName, self.notBefore,\
					self.notAfter,self.aki,self.ski,self.keyFileName,self.keyFileName, self.ip4Strings,\
					self.ip6Strings, self.asStrings,self.path_CA_cert, "rsync://"+REPO_PATH+"/"+self.SIA)
			return
			
		#If this isn't a trust anchor.
		self.nextChildSN = 0
		self.id = parent.getNextChildSN()
		self.myFactory = myFactory
		self.bluePrintName = myFactory.bluePrintName
		self.parent = parent
		self.notBefore = datetime.now()
		self.notAfter = datetime.fromtimestamp(time()+myFactory.ttl)
		self.nickName= self.bluePrintName+str(self.id)
		self.commonName = parent.commonName+"."+self.nickName
		self.aki = parent.ski
		
		#List initialization
		self.children = []
		self.manifests = []
		self.roas = []
		self.crl = []

		if factory.breakAway:
			self.SIA = self.myFactory.serverName + "/"+self.nickName
		else:
			self.SIA = parent.SIA + "/" +self.nickName
			
		
		#Generate our keyfile by creating a parallel repository for keys
		#Keys are placed under a directory of their SIA. For example
		#IANA's key should be in IANA/IANA.p15, APNIC's, should be in something
		#like IANA/APNIC1/APNIC1.p15
		self.keyFileName = OBJECT_PATH+"/keys/"+self.SIA+"/"+self.nickName+".p15"
		command_string = "../cg/tools/gen_key "+self.keyFileName+ " 1024"
		#Execute the gen_key command, create the directory if it needs to
		dir_path = OBJECT_PATH+"/keys/"+self.SIA+"/"
		if not os.path.exists(dir_path):
			os.system("mkdir -p "+ dir_path)	
		os.system(command_string)
		
		#set our ski based on the hash of the public key in our keyfile
		#result from .p15-> hash(public_key) which is a hex string
		self.ski = generate_ski(self.keyFileName)
		
		try:
			#tuple of type([ipv4 netaddrs,...], [ipv6 netaddrs,...], [as_nums(start,end),...])
			self.ResourcesOwned = parent.allocate(myFactory.ipv4List, myFactory.ipv6List, myFactory.asList)
		except:
			print "Error occured in allocating resources for this CA_object"

		self.AIA = parent.path_CA_cert
		#crlfileName.... computed by B64(parent.ski)
		self.CRLDP = REPO_PATH+"/"+parent.SIA+"/"+base64.urlsafe_b64encode(parent.ski)+".crl"
		self.path_CA_cert = REPO_PATH+"/"+parent.SIA+"/"+base64.urlsafe_b64encode(self.ski)+".cer"
		
		#Check if the directory is create yet for our Certificate
		#If it's not made make it. Since cert tools won't create dirs
		dir_path= REPO_PATH+"/"+parent.SIA+"/"
		if not os.path.exists(dir_path):
			os.system("mkdir -p "+dir_path)
		
		#Parse out the resources we've been allocated to blocks and strings for our certificate
		#Create lists for our blocks for sub_allocation to child ca's.
		self.ip4ResourcesFree = []; self.ip6ResourcesFree = [] ;self.asResourcesFree = []
		self.ip4Strings = []; self.ip6Strings = []; self.asStrings = []
		self.parseResources()

		print "about to create" + self.path_CA_cert
		
		self.certificate = CA_cert(self.id,parent.commonName, \
				self.commonName, self.notBefore,self.notAfter,\
				self.aki,self.ski,self.keyFileName, parent.keyFileName,\
				self.ip4Strings, self.ip6Strings, self.asStrings, \
				self.path_CA_cert, "rsync://"+self.CRLDP,\
				"rsync://"+REPO_PATH+"/"+self.SIA,"rsync://"+self.AIA)
	
		
	def parseResources(self):
		#IPV4
		for ipRange in self.ResourcesOwned[0]:
			#Put the netaddr into a block and add it to our list of free resources
			self.ip4ResourcesFree.append(Resource_Block(ipRange, self.commonName))
			#Get the string representation of our address and add it to the list we'll pass to CA_cert
			self.ip4Strings.append(str(ipRange))
		#IPv6 same deal as above
		for ipRange in self.ResourcesOwned[1]:
			self.ip6ResourcesFree.append(Resource_Block(ipRange, self.commonName))
			self.ip6Strings.append(str(ipRange))
		#AS numbers
		for asRange in self.ResourcesOwned[2]:
			#Put the integer tuple into a block and add it to our list of free resources
			self.asResourcesFree.append(Resource_Block(asRange, self.commonName))
			#Get the string representation of our address and add it to the list we'll pass to CA_cert
			self.asStrings.append(str(asRange[0])+"-"+str(asRange[1]))
		
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
		
		
