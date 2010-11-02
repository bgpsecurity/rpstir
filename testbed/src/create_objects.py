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
CONFIG_PATH = OBJECT_PATH+'/configs/'
DEBUG_ON = True
RSYNC_EXTENSION = "r:rsync://"
SECONDS_IN_DAY = 86400
#
# This is a utility function that will write the configuration file
#  that will be fed to the create_object code
#
def writeConfig(obj):
    # Use introspection to print out all the member variables and their values to a file
    if not os.path.exists(CONFIG_PATH):
        os.system('mkdir -p ' + CONFIG_PATH)
    fn = obj.outputfilename.split('/')
    file = fn[-1]
    f = open(CONFIG_PATH + file + ".cfg", 'w')
    
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
            elif member == 'roaipv4' or member == 'roaipv6':
                try:
                    ip,value = val.split('%')
                except ValueError:
                    value = None
                if value is not None:
                    fileBuf += '%s=%s%%%s\n' % (member, ip,value)
                else:
                    fileBuf += '%s=%s\n' % (member, val)                    
            elif member == 'notBefore' or member == 'notAfter' \
                    or  member == 'thisupdate' or member == 'nextupdate':
                fileBuf += '%s=%s\n' % (member,val.strftime("%Y%m%d%H%M%SZ"))
            elif member == 'fileList':
                fileBuf += '%s=%s\n' % (member, ','.join(val))
            else:
                fileBuf+= '%s=%s\n' % (member,val)
        else:
            fileBuf+='%s=%s\n' % (member,val)
            
    f.write(fileBuf)
    f.close()

#
# Drops the last set of = signs off the returned string. These are just 
#  padding information specified by the RFC for the b64 encoding  and 
#  currently don't are about them
#
def b64encode_wrapper(toPass):
    ret = base64.urlsafe_b64encode(toPass)
    while ret[-1] == '=':
        ret = ret[:-1]
    return ret

#
# This is a generic function that calls create_object
#
def create_binary(obj, xargs):
    fn = obj.outputfilename.split('/')
    file = fn[-1]
    s = './create_object -f %s%s.cfg ' % (CONFIG_PATH,file)
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
# Calls the gen_hash C executable and grabs the STDOUT from it
#  and returns it as the hash of the contents of the filename
#
# Author: Brenton Kohler 
#
def generate_file_hash(filename):
    s = "./gen_hash -n %s" % filename
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
        self.notAfter = datetime.datetime.fromtimestamp(time()+myFactory.ttl*SECONDS_IN_DAY)
        
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
        self.outputfilename = dir_path+b64encode_wrapper(self.ski)+".cer"
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
        #For aia cut off the portion that contains the repoitory path to create an rsync url
        self.aia   = "r:rsync://"+parent.path_CA_cert[len(REPO_PATH)+1:]
        self.crldp = "rsync://"+parent.SIA_path+"/"+b64encode_wrapper(parent.certificate.ski)+".crl"
        Certificate.__init__(self,parent, myFactory,sia_path,serial)
        self.sia = "r:rsync://"+sia_path+",m:rsync://"+sia_path+"/"+b64encode_wrapper(self.ski)+".mft"
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

        path_sia = parent.SIA_path+"/"+nickName
        self.crldp = "rsync://"+parent.SIA_path+"/"+b64encode_wrapper(parent.certificate.ski)+".crl"
        Certificate.__init__(self,parent,myFactory,path_sia,serial)
        
        #Set our SIA based on the hash of our public key, which will be the name
        #of the ROA or Manifest this EE will be signing 
        if myFactory.bluePrintName == "Manifest-EE":
            self.sia = "s:rsync://"+parent.SIA_path+"/"+b64encode_wrapper(parent.certificate.ski)+".mft"
        else:
            self.sia = "s:rsync://"+parent.SIA_path+"/"+b64encode_wrapper(self.ski)+".roa"
              
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
        Certificate.__init__(self,parent,myFactory,sia_path,serial)
        self.sia = "r:rsync://"+sia_path+",m:rsync://"+sia_path+"/"+b64encode_wrapper(self.ski)+".mft"
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
class Manifest(CMS):
    def __init__(self, parent, myFactory):
        
        eeCertificate = EE_cert(parent,myFactory)
        self.manNum         = eeCertificate.serial
        self.thisupdate      = datetime.datetime.now()
        #Not sure on this nextUpdate time frame
        self.nextupdate      = datetime.datetime.fromtimestamp(time()+parent.myFactory.ttl*SECONDS_IN_DAY)
        #Chop off our rsync:// portion and append the repo path
        self.outputfilename = REPO_PATH+"/"+parent.SIA_path+"/"+b64encode_wrapper(parent.certificate.ski)+".mft"
        
        dirname = REPO_PATH+"/"+parent.SIA_path
        fileList = []
        for f in os.listdir(dirname):
            if os.path.isfile(os.path.join(dirname, f)):
                fileList.append(f+"%"+generate_file_hash(dirname+"/"+f))
        
        self.fileList = fileList
        CMS.__init__(self, eeCertificate.outputfilename,eeCertificate.subjkeyfile)

        writeConfig(self)
        create_binary(self, "MANIFEST")
#
# The ROA class. Inherits from CMS
#
class Roa(CMS):
    def __init__(self,myFactory,ee_object):
        #Pull the info we need from our ee_object
        self.asID           = ee_object.subAllocateAS(myFactory.asid)
        self.roaipv4        = ee_object.subAllocateIP4(myFactory.ROAipv4List)
        self.roaipv6        = ee_object.subAllocateIP6(myFactory.ROAipv6List)
        self.outputfilename = REPO_PATH+"/"+ee_object.path_ROA
        #Make our directory to place our ROA if it doesn't already exist
        dir_path = REPO_PATH+"/"+ee_object.parent.SIA_path+"/"
        
        #Can safely remove this if it works in the main loop
        #if not os.path.exists(dir_path):
        #    os.system("mkdir -p "+ dir_path)
        CMS.__init__(self, ee_object.certificate.outputfilename, ee_object.certificate.subjkeyfile)

        writeConfig(self)
        create_binary(self, "ROA")

#
# The CRL class.
#
class Crl:
    def __init__(self, parent):

        self.parentcertfile  = parent.path_CA_cert
        self.parentkeyfile   = parent.certificate.subjkeyfile
        self.issuer          = parent.commonName
        self.thisupdate      = datetime.datetime.now()
        #Not sure on this nextUpdate time frame
        self.nextupdate      = datetime.datetime.fromtimestamp(time()+parent.myFactory.ttl*SECONDS_IN_DAY)
        self.crlnum          = parent.getNextChildSN()
        self.revokedcertlist = []
        self.aki             = parent.certificate.ski
         
        #Create the output file directory if it doesn't exist
        dir_path  = REPO_PATH+"/"+parent.SIA_path+"/"
        self.outputfilename = dir_path+b64encode_wrapper(parent.certificate.ski)+".crl"
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
