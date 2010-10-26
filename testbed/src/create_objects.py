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
#  * Contributor(s):  Brenton Kohler
#  *
#  * ***** END LICENSE BLOCK ***** */

import datetime, os, sys
from subprocess import Popen
import subprocess

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
    def __init__(self, serial, issuer, subject, notBefore, notAfter, aki,
                 ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename):
        self.serial         = serial
        self.issuer         = issuer
        self.subject        = subject
        self.notBefore      = notBefore
        self.notAfter       = notAfter
        self.aki            = aki
        self.ski            = ski
        self.subjkeyfile    = subjkeyfile
        self.parentkeyfile  = parentkeyfile
        self.ipv4           = ipv4
        self.ipv6           = ipv6
        self.as             = as
        self.outputfilename = outputfilename
        
#
# The CA Certificate class. Inherits from Certificate
#
class CA_cert(Certificate):
    def __init__(self, serial,issuer, subject, notBefore, notAfter, aki,
                 ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename, crldp, sia, aia):
        self.crldp = crldp
        self.sia   = sia
        self.aia   = aia
        Certificate.__init__(self,serial,issuer, subject, notBefore, notAfter, aki,
                    ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename)
        writeConfig(self)
        create_binary(self, "CERTIFICATE selfsigned=False")

#
# The EE certificate class. Inherits from Certificate
#
class EE_cert(Certificate):
    def __init__(self, serial,issuer, subject, notBefore, notAfter, aki,
                 ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename, crldp, sia):
        self.sia   = sia
        self.crldp = crldp
        Certificate.__init__(self,serial,issuer, subject, notBefore, notAfter, aki,
                    ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename)
        writeConfig(self)
        create_binary(self, "CERTIFICATE selfsigned=False")

#
# The SS certificate class. Inherits from Certificate
#
class SS_cert(Certificate):
    def __init__(self, serial,issuer, subject, notBefore, notAfter, aki,
                 ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename, sia):
        self.sia = sia
        Certificate.__init__(self, serial, issuer, subject, notBefore, notAfter, aki,
                    ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename)
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
    def __init__(self, manNum, thisUpdate, nextUpdate, subjFile, fileList,
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
class roa(CMS):
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
