#!/usr/bin/python
# /* ***** BEGIN LICENSE BLOCK *****
#  *
#  * BBN Address and AS Number PKI Database/repository software
#  * Version 3.0-beta
#  *
#  * US government users are permitted unrestricted rights as
#  * defined in the FAR.
#  *
#  * This software is distributed on an "AS IS" basis, WITHOUT
#  * WARRANTY OF ANY KIND, either express or implied.
#  *
#  * Copyright (C) Raytheon BBN Technologies Corp. 2008-2010.
#  * all Rights Reserved.
#  *
#  * Contributor(s):  Ryan Caloras, Brenton Kohler
#  *
#  * ***** END LICENSE BLOCK ***** */

import datetime, os, sys
from subprocess import Popen
import subprocess
from time import time
import base64

OBJECT_PATH = "../objects"
REPO_PATH = OBJECT_PATH+"/REPOSITORY"
DEBUG_ON = True

#
# This is a utility function that will write the configuration file
#  that will be fed to the create_object code
#
def writeConfig(obj):
    # Use introspection to print out all the member variables and their values to a file
    f = open(obj.outputfilename + ".cfg", 'w')
    
    #Gets all the attributes of this class that are only member variables(not functions)
    members = [attr for attr in dir(obj) if not callable(getattr(obj,attr))
               and not attr.startswith("__")]

    #builds the string to print to the file
    fileBuf = ''
    name = obj.__class__.__name__
    if name == 'EE_cert':
        fileBuf += 'type=ee\n'
    elif name == 'CA_cert' or name == 'SS_cert' or name == 'Certificate':
        fileBuf += 'type=ca\n'

    # loops through all member of this class and writes them to the config file
    for member in members:
        val = getattr(obj,member)
        if val is not None:
            if member == 'issuer' or member == 'subject':
                #deal with the issuer and subject name
                try:
                    name,ser = val.split('%')
                except ValueError:
                    ser = None
                if ser is not None:
                    fileBuf += '%s=%s%%%s\n' % (member, name,ser)
                else:
                    fileBuf += '%s=%s\n' % (member, val)
            
            elif member == 'ipv4' or member == 'ipv6' or member == 'as':
                fileBuf += '%s=%s\n' % (member,",".join(val))
            elif member == 'notBefore' or member == 'notAfter':
                fileBuf += '%s=%s\n' % (member,val.strftime("%Y%m%d%H%M%SZ"))
            else:
                fileBuf+= '%s=%s\n' % (member,val)
        else:
            fileBuf+='%s=%s\n' % (member,val)
            
    f.write(fileBuf)
    f.close()

#
# This is a generic function that calls create_object
#
def create_binary(obj, xargs):
    s = './create_object -f %s.cfg ' % obj.outputfilename
    s += xargs
    os.system(s)

#
# Calls the gen_hash C executable and grabs the STDOUT from it
#  and returns it as the SKI
#
# Author: Brenton Kohler 
#
def generate_ski(filename):
    s = "./gen_hash -f %s" % filename
    p = Popen(s, shell=True, stdout=subprocess.PIPE)
    stdout = p.communicate()[0]
    return stdout


#
# The certificate class
# 
class Certificate:
    
    #Constructs a certificate object by executing and generating
    #the appropriate files and information. If it's a CA certificate
    #its reference will be stored and used within the CA_Object
    def __init__(self,parent, myFactory,sia_path, serial):
        
        self.serial = serial
        
        #Local variable to help with naming conventions
        nickName = myFactory.bluePrintName+"-"+str(self.serial)
        
        #Certificate lifetime and expiration info
        self.notBefore = datetime.datetime.now()
        self.notAfter = datetime.datetime.fromtimestamp(time()+myFactory.ttl)
        
        #Set our subject key file name and generate the key
        #Also check the directory first, and create it if it doesn't exist
        dir_path = OBJECT_PATH+"/keys/"+sia_path
        self.subjkeyfile = dir_path+"/"+nickName+".p15"
        command_string = "../../cg/tools/gen_key "+self.subjkeyfile+ " 1024"
        if not os.path.exists(dir_path):
            os.system("mkdir -p "+ dir_path)
        os.system(command_string)
        if DEBUG_ON:
            print command_string      
            
        #Generate our ski by getting the hash of the public key 
        #Result from .p15 -> hash(public_key) which is a hex string
        self.ski = generate_ski(self.subjkeyfile)
        if DEBUG_ON:
            print self.ski

        #Set the name we will write to file depending on if
        #this is a CA_cert, EE_cert, SS_cert. Also check if it exists
        if isinstance(self,CA_cert):
            dir_path  = REPO_PATH+"/"+parent.SIA_path+"/"
        elif isinstance(self,EE_cert):
            dir_path = REPO_PATH+"/EE/"+parent.SIA_path+"/"
        elif isinstance(self,SS_cert):
            dir_path = REPO_PATH+"/"+myFactory.serverName+"/"
        #Create the output file directory if it doesn't exist
        self.outputfilename = dir_path+base64.urlsafe_b64encode(self.ski)+".cer"
        if DEBUG_ON:
            print "outputfilename = "+self.outputfilename
        if not os.path.exists(dir_path):
            os.system("mkdir -p " + dir_path)
        
        #Initilization based on if you're a TA or not
        #EE and CA else SS
        if parent != None:
            self.issuer = parent.commonName
            self.subject = parent.commonName+"."+nickName
            self.parentkeyfile = parent.certificate.subjkeyfile
            self.aki = parent.certificate.ski
            self.ipv4 = parent.subAllocateIP4(myFactory.ipv4List)
            self.ipv6 = parent.subAllocateIP6(myFactory.ipv6List)
            self.as = parent.subAllocateAS(myFactory.asList)
            
        else:
            self.issuer = nickName
            self.subject = nickName
            self.parentkeyfile = self.subjkeyfile
            self.aki = self.ski
            self.ipv4 = myFactory.ipv4List
            self.ipv6 = myFactory.ipv6List
            self.as = myFactory.asList
#
# The CA Certificate class. Inherits from Certificate
#
class CA_cert(Certificate):
    def __init__(self, parent, myFactory):
        
        serial = parent.getNextChildSN()
         #Local variable to help with naming conventions
        nickName = myFactory.bluePrintName+"-"+str(serial)
        
        if myFactory.breakAway == True:
            sia_path = myFactory.serverName + "/"+nickName
        else:
            sia_path = parent.SIA_path + "/" +nickName
    

        #setup our cert addresses for rsync
        self.aia   = "r:rsync://"+parent.path_CA_cert
        self.crldp = "r:rsync://"+REPO_PATH+"/"+parent.SIA_path+"/"+base64.urlsafe_b64encode(parent.certificate.ski)+".crl"
        self.sia = "r:rsync://"+REPO_PATH+"/"+sia_path
        Certificate.__init__(self,parent, myFactory,sia_path,serial)
        writeConfig(self)
        create_binary(self, "CERTIFICATE selfsigned=False")

#
# The EE certificate class. Inherits from Certificate
#
class EE_cert(Certificate):
    def __init__(self, parent, myFactory):
        
        serial = parent.getNextChildSN()
         #Local variable to help with naming conventions
        nickName = "EE-"+str(serial)

        sia__path = parent.SIA_path+"/"+nickName
        self.crldp = "r:rsync://"+REPO_PATH+"/"+parent.SIA_path+"/"+base64.urlsafe_b64encode(parent.certificate.ski)+".crl"
        Certificate.__init__(self,pqrent,myFactory,sia_path,serial)
        #Set our SIA based on the hash of our public key, which will be the name of the ROA this EE will be inside of.
        self.sia = "r:rsync://"+REPO_PATH+"/"+parent.SIA_path+"/"+base64.urlsafe_b64encode(self.ski)+".roa"
        writeConfig(self)
        create_binary(self, "CERTIFICATE selfsigned=False")

#
# The SS certificate class. Inherits from Certificate
#
class SS_cert(Certificate):
    def __init__(self, parent, myFactory):
      
        #Iana should have zero!
        serial = 0
         #Local variable to help with naming conventions
        nickName = myFactory.bluePrintName+"-"+str(serial)
  
        sia_path = myFactory.serverName + "/"+nickName
        self.sia = "r:rsync://"+REPO_PATH+"/"+sia_path
        Certificate.__init__(self,parent,myFactory,sia_path,serial)
        writeConfig(self)
        create_binary(self, "CERTIFICATE selfsigned=True")

#
# The generic CMS class
#
class CMS:
    def __init__(self, EECertLocation, EEKeyLocation):
        self.EECertLocation = EECertLocation
        self.EEKeyLocation = EEKeyLocation

#
# The Manifest class. Inherits from CMS
#
class manifest(CMS):
    def __init__(self, manNum, thisUpdate, nextUpdate, outputfilename, fileList,
                 EECertLocation, EEKeyLoation):
        self.manNum         = manNum
        self.thisUpdate     = thisUpdate
        self.nextUpdate     = nextUpdate
        self.outputfilename = outputfilename
        self.fileList       = fileList
        CMS.__init__(self, EECertLocation, EEKeyLocation)

        writeConfig(self)
        create_binary(self, "MANIFEST")

#
# The ROA class. Inherits from CMS
#
class Roa(CMS):
    def __init__(self, asID, ipv4, ipv6, EECertLocation, EEKeyLocation, outputfilename):
        self.asID           = asID
        self.ipv4           = ipv4
        self.ipv6           = ipv6
        self.outputfilename = outputfilename
        CMS.__init__(self, EECertLocation, EEKeyLocation)

        writeConfig(self)
        create_binary(self, "ROA")

#
# The CRL class.
#
class crl:
    def __init__(self, parentcertfile, parentkeyfile, issuer, thisupdate, nextupdate,
                 crlnum, revokedcertlist, aki, signatureValue, outputfilename):
        self.parentcertfile  = parentcertfile
        self.parentkeyfile   = parentkeyfile
        self.issue           = issuer
        self.thisupdate      = thisupdate
        self.nextupdate      = nextupdate
        self.crlnum          = crlnum
        self.revokedcertlist = revokedcertlist
        self.aki             = aki
        self.signatureValue  = signatureValue
        self.outputfilename  = outputfilename

        writeConfig(self)
        create_binary(self, "CRL")

#
# A testing function to help determine if above classes
#   and functionality is correctly working
#
def main():
    #create some dummy certificates
    c = Certificate(234,
                    ['name','value'],
                    ['name','value'],
                    datetime.datetime.now(),
                    datetime.datetime.now(),
                    '0xffdd4398764433983322099110',
                    '0x12df45ac65bf9876ff',
                    '../templates/EE.p15',
                    '../templates/TA.p15',
                    ['1.2.3.4-1.2.5.255','10.0.5/24', '10.0.4.0-10.0.5.249'],
                    ['0a00:0080/25', '2220::/13,3330::/13','1111:1111::/32','2222::-2223::'],
                    '1-16,40,33,22,60-156',
                    'c.cer')
  
    ss = SS_cert(23,
                 ['name','value'],
                 ['name','value'],
                 datetime.datetime.now(),
                 datetime.datetime.now(),
                 '0xffdd4398764433983322099110',
                 '0x12df45ac65bf9876ff',
                 '../templates/EE.p15',
                 '../templates/TA.p15',
                 ['1.2.3.4-1.2.5.255','10.0.5/24', '10.0.4.0-10.0.5.249'],
                 ['0a00:0080/25', '2220::/13,3330::/13','1111:1111::/32','2222::-2223::'],
                 '1-16,40,33,22,60-156',
                 'ss.cer',
                 'm:roa-pki://home/testdir, r:rsync://my/new/home/dir/for/ca/stuff')
    
    ee = EE_cert(56,
                 ['name','value'],
                 ['name','value'],
                 datetime.datetime.now(),
                 datetime.datetime.now(),
                 '0xffdd4398764433983322099110',
                 '0x12df45ac65bf9876ff',
                 '../templates/EE.p15',
                 '../templates/TA.p15',
                 ['1.2.3.4-1.2.5.255','10.0.5/24', '10.0.4.0-10.0.5.249'],
                 ['0a00:0080/25','1111:1111::/32','2222::-2223::'],
                 '1-16,40,33,22,60-156',
                 'ee.cer',
                 '/home/ksirois/rpki/trunk/testcases, /home/testdir/APNIC',
                 'm:roa-pki://home/testdir, r:rsync://my/new/home/dir/for/ca/stuff')

    ca = CA_cert(234678,
                 ['name','val'],
                 ['name','value'],
                 datetime.datetime.now(),
                 datetime.datetime.now(),
                 '0xffdd4398764433983322099110',
                 '0x12df45ac65bf9876ff',
                 '../templates/EE.p15',
                 '../templates/TA.p15',
                 ['1.2.3.4-1.2.5.255','10.0.5/24', '10.0.4.0-10.0.5.249'],
                 ['0a00:0080/25','1111:1111::/32','2222::-2223::'],
                 '1-16,40,33,22,60-156',
                 'ca.cer',
                 'crldp',
                 'm:roa-pki://home/testdir, r:rsync://my/new/home/dir/for/ca/stuff','aia')


#Fire off the test
if __name__ == '__main__':
    main()
