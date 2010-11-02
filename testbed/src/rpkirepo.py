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
from create_objects import *

OBJECT_PATH = "../objects"
REPO_PATH = OBJECT_PATH+"/REPOSITORY"
DEBUG_ON = False
RSYNC_EXTENSION = "r:rsync://"

class Factory:
    def __init__(self, bluePrintName = "", ipv4List = [], ipv6List= [],\
            asList = [], childSpec = [()], serverName = "", breakAway = False, ttl = 0):
        # Particular type of CA object as specified in config file
        self.bluePrintName = bluePrintName
        
        
        #Different for IANA. These are directly set to the cert
        #See the certificate class constructor for reference
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
        if DEBUG_ON:
            print "creating a CA_object as specified by "+ self.bluePrintName
        return CA_Object(self,parent)
#
# The ROA Factory class. Inherits from Certificate.
#
class ROA_Factory(Factory):
    def __init__(self, bluePrintName = "", ipv4List = [], ipv6List= [], \
            asList = [], childSpec = [()], serverName = "", \
            breakAway = False, ttl = 0, ROAipv4List =[], ROAipv6List = [], \
            asid = 0):
        
        #Call the factory constructor to initialize inherited args
        Factory.__init__(self, bluePrintName, ipv4List, ipv6List, asList,\
                childSpec, serverName, breakAway, ttl = 0)
        
        #ROA specific
        self.ROAipv4List = ROAipv4List
        self.ROAipv6List = ROAipv6List
        self.asid = asid
    def create(self, parent):
        if DEBUG_ON:
            print "creating a ROA for "+ self.bluePrintName
            
        ee_object = EE_Object(self, parent)
        return Roa(self,ee_object) 
 
#Takes a netAddrList and converts it to a list of IP range strings for certificates
def parseIPForCert(self, netAddrList):
    ipStrings = []
    for ipRange in netAddrList:
        #Get the string representation of our address and add it to the list we'll pass to CA_cert
        ipStrings.append(str(ipRange))
    return ipStrings
    
#Takes an as list and converts it to a list of AS range strings for certificates
def parseASForCert(self, intTupleList):
    asStrings = []
    for asRange in intTupleList:
        #Get the string representation of our address and add it to the list we'll pass to CA_cert
        asStrings.append(str(asRange[0])+"-"+str(asRange[1]))
    return asStrings
       

class Resource_Block:
    def __init__(self, range, ca_name, block_id= 0, allocated=False):
        #integer tuple or netaddr.IPRange
        self.range = range
        self.ca_name = ca_name
        #not sure if a unique identifier is needed yet
        self.block_id = block_id
        self.allocated = allocated

class EE_Object:
    def __init__(self, myFactory, parent=None):

        self.bluePrintName = myFactory.bluePrintName
        self.myFactory = myFactory
        self.parent = parent
        
        #List initialization
        self.children = []
        self.ip4ResourcesFree = []; self.ip6ResourcesFree = [] ;self.asResourcesFree = []
        #Intialize our certificate
        self.certificate = EE_cert(parent,myFactory)
        
        #Grab what I need from the certificate 
        #Obtain just the SIA path and cut off the r:rsync
        self.SIA_path = self.certificate.sia[len(RSYNC_EXTENSION):]
        self.id = self.certificate.serial 
        self.path_ROA = self.SIA_path
        
        #FIX ME add some kind of string list to Netaddr Function for allocation
        self.ipv4ResourcesFree = self.certificate.ipv4
        self.ipv6ResourcesFree = self.certificate.ipv6
        self.asResourcesFree = self.certificate.as 
    
    #Hard coded suballocation currently, need to implement actual allocation
    def subAllocateIP4(self,iplist):
        return "0.0.0.0/16"
    def subAllocateIP6(self,iplist):
        return "1::/16"
    def subAllocateAS(self, asList):
        return 1
    
    def allocate(self, ipv4List, ipv6List, asList):
        return (self.subAllocateIP4(ipv4List),self.subAllocateIP6(ipv6List),self.subAllocateAS(asList))
    
    
class CA_Object:

    def __init__(self, myFactory, parent=None):

        self.nextChildSN = 0
        self.bluePrintName = myFactory.bluePrintName
        self.myFactory = myFactory
        self.parent = parent
        #List initialization
        self.children = []
        self.manifests = []
        self.roas = []
        self.crl = []
        self.ip4ResourcesFree = []; self.ip6ResourcesFree = [] ;self.asResourcesFree = []
        #Intialize our certificate
        if parent != None:
            self.certificate = CA_cert(parent,myFactory)
        else:
            self.certificate = SS_cert(parent,myFactory)    
        #Grab what I need from the certificate 
        #Obtain just the SIA path and cut off the r:rsync://
        sia_list = self.certificate.sia[len(RSYNC_EXTENSION):].split(",")
        self.SIA_path = sia_list[0]
        self.manifest_path = sia_list[1][len(RSYNC_EXTENSION):]
        self.id = self.certificate.serial 
        self.path_CA_cert = self.certificate.outputfilename
        self.nickName= self.myFactory.bluePrintName+"-"+str(self.id)
        if parent != None:
            self.commonName = parent.commonName+"."+self.nickName
        else:
            self.commonName = self.nickName
        
        #FIX ME add some kind of string list to Netaddr Function for allocation
        self.ipv4ResourcesFree = self.certificate.ipv4
        self.ipv6ResourcesFree = self.certificate.ipv6
        self.asResourcesFree = self.certificate.as 
        
    def subAllocateIP4(self,iplist):
        return parseIPForCert(self,[netaddr.IPRange("0.0.0.0","0.0.0.255")])
    def subAllocateIP6(self,iplist):
        return parseIPForCert(self,[netaddr.IPRange("1::0","255::0")])
    def subAllocateAS(self, asList):
        return parseASForCert(self,[(0,1)])
    
    def allocate(self, ipv4List, ipv6List, asList):
        return (self.subAllocateIP4(ipv4List),self.subAllocateIP6(ipv6List),self.subAllocateAS(asList))
        
        
    
    def getNextChildSN(self):
        nextChild = self.nextChildSN
        self.nextChildSN += 1
        return nextChild
        
        
