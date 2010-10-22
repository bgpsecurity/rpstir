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

#Imports
import datetime, os, sys

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
    # This is a utility function that will write the configuration file
    #  that will be fed to the create_object code
    #
    def writeConfig(self):
        # Use introspection to print out all the member variables and their values to a file
        f = open(self.outputfilename + ".cfg", 'w')

        #Gets all the attributes of this class that are only member variables(not functions)
        members = [attr for attr in dir(self) if not callable(getattr(self,attr))
                   and not attr.startswith("__")]

        #builds the string to print to the file
        fileBuf = ''
        name = self.__class__.__name__
        if name == 'EE_cert':
            fileBuf += 'type=ee\n'
        else:
            fileBuf += 'type=ca\n'

        # loops through all member of this class and writes them to the config file
        for member in members:
            if getattr(self,member) is not None:
                if member == 'issuer' or member == 'subject':
                    if getattr(self, member)[1] is not None:
                        fileBuf += '%s=%s%%%s\n' % (member, getattr(self,member)[0],
                                                    getattr(self,member)[1])
                    else:
                        fileBuf += '%s=%s\n' % (member, getattr(self,member)[0])
                elif member == 'ipv4' or member == 'ipv6' or member == 'as':
                    fileBuf += '%s=%s\n' % (member,",".join(getattr(self,member)))
                elif member == 'notBefore' or member == 'notAfter':
                    fileBuf += '%s=%s\n' % (member,getattr(self,member).strftime("%Y%m%d%H%M%S"))
                else:
                    fileBuf+= '%s=%s\n' % (member,getattr(self,member))
            else:
                fileBuf+='%s=%s\n' % (member,'')
            
        f.write(fileBuf)
        f.close()

    #
    # The function to call in order to create a binary based on this
    #  certificate object
    #
    def createBinary(self):
        s = './create_object -f %s.cfg' % self.outputfilename
        name = self.__class__.__name__
        if name == 'SS_cert':
            s += ' CERTIFICATE selfsigned=true'
        else:
            s += ' CERTIFICATE selfsigned=false'

        #s += ' -f %s.cfg' % self.outputfilename
        print(s)
        os.system(s)

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

#
# The SS certificate class. Inherits from Certificate
#
class SS_cert(Certificate):
    def __init__(self, serial,issuer, subject, notBefore, notAfter, aki,
                 ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename, sia):
        self.sia = sia
        Certificate.__init__(self, serial, issuer, subject, notBefore, notAfter, aki,
                    ski, subjkeyfile, parentkeyfile, ipv4, ipv6, as, outputfilename)



#
# A testing function to help determine if above classes
#   and functionality is correctly working
#
def main():
    #create some dummy certificates
    c = Certificate(234,['name','value'], ['name','value'], datetime.datetime.now(),
                    datetime.datetime.now(), 'aki','ski', 'sKeyFile', 'parentkeyfile',
                    ['1.2.3.4-1.2.5.255', '10.0.5/24', '10.0.4.0-10.0.5.249'],
                    ['0a00:0080/25', '2220::/13,3330::/13,
                     '1111:1111::/32','AAA1::-AAA2:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
                     '2222::-2223::'],
                    'asNums', 'c.cer')

    ss = SS_cert(23,['name','value'], ['name','value'], datetime.datetime.now(),
                 datetime.datetime.now(), 'aki', 'ski', 'sKeyFile', 'parentkeyfile',
                 ['1.2.3.4-1.2.5.255', '10.0.5/24', '10.0.4.0-10.0.5.249'],
                 ['0a00:0080/25', '2220::/13,3330::/13,
                  '1111:1111::/32','AAA1::-AAA2:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
                  '2222::-2223::'],
                 'asNums', 'ss.cer','sia')
    
    ee = EE_cert(56,['name','value'], ['name','value'], datetime.datetime.now(),
                 datetime.datetime.now(), 'aki', 'ski', 'sKeyFile', 'parentkeyfile',
                 ['1.2.3.4-1.2.5.255','10.0.5/24', '10.0.4.0-10.0.5.249'],
                 ['0a00:0080/25',
                  '1111:1111::/32',
                  'AAA1::-AAA2:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF','2222::-2223::'],
                 'asNums', 'ee.cer','crldp','ee_sia')

    ca = CA_cert(234678,['name','val'], ['name','value'], datetime.datetime.now(),
                 datetime.datetime.now(), 'aki', 'ski', 'sKeyFile', 'parentkeyfile',
                 ['1.2.3.4-1.2.5.255','10.0.5/24', '10.0.4.0-10.0.5.249'],
                 ['0a00:0080/25',
                  '1111:1111::/32','AAA1::-AAA2:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF',
                  '2222::-2223::'],
                 'asNums','ca.cer','crldp','sia','aia')

    c.writeConfig()
    ss.writeConfig()
    ee.writeConfig()
    ca.writeConfig()

    c.createBinary()
    ss.createBinary()
    ca.createBinary()
    ee.createBinary()
    



#Fire off the test
if __name__ == '__main__':
    main()
