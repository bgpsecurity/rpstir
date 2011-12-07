#!/usr/bin/python
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
# * Contributor(s):  Ryan Caloras (rcaloras@bbn.com), Brenton Kohler
# * Date: 10/21/2010
# *
# * ***** END LICENSE BLOCK ***** */

from datetime import datetime
from time import time
from Queue import Queue 
from rpkirepo import *
import ConfigParser
from netaddr import IPAddress, IPNetwork, IPRange

#Globals for repository specified by configuration file
#These are set once while parsing the .ini
MAX_DEPTH = None
MAX_NODES = None
FACTORIES = {}

#
# Parses the val as a string like AFRINIC,1%APNIC,2%RIPE,2...
# Stores result as a tuple in the list toMode
#
def parse(toMod, val):
        # parse the string like AFRINIC,1%APNIC,2%RIPE,2...
        tup = val.split(',')
        for i in tup:
                try:
                        #split the individual groups
                        one,two=i.split('%')
                        x = (one.strip(),int(two.strip()))
                        toMod.append(x)
                except ValueError:
                        print 'A value error occurred for: %s' %(i)


def configuration_parser(factory_dict,fileName):
        # construct the configparser and read in the config file
        config = ConfigParser.ConfigParser()
        config.read(fileName)

        sections = config.sections()

        try:
                # loop over all sections and options and build factories
                for section in sections:
                        options = config.options(section)
                        child      = []
                        ipv4       = []
                        ipv6       = []
                        server     = ''
                        breakA     = ''
                        t          = 0
                        as_list         = []
                        a          = 0
                        roav4l     = []
                        roav6l     = []
                        subjkeyfile= None
                        
                        for opt in options:
                                if opt == 'childspec':
                                        val = config.get(section,opt)
                                        parse(child,val)
                                elif opt == 'ipv4list':
                                        l = config.get(section,opt)
                                        parse(ipv4,l)
                                elif opt == 'ipv6list':
                                        l = config.get(section,opt)
                                        parse(ipv6,l)
                                elif opt == 'aslist':
                                        l = config.get(section,opt)
                                        parse(as_list,l)
                                elif opt == 'servername':
                                        server = config.get(section,opt)
                                elif opt == 'breakaway':
                                        breakA = config.get(section,opt)
                                elif opt == 'ttl':
                                        t = config.getint(section,opt)
                                elif opt == 'max_depth':
                                        global MAX_DEPTH
                                        MAX_DEPTH = config.getint(section,opt)
                                elif opt == 'max_nodes':
                                        global MAX_NODES
                                        MAX_NODES=config.getint(section,opt)
                                elif opt == 'roaipv4list':
					# FIXME: maxlength not yet supported
                                        l = config.get(section,opt)
                                        parse(roav4l, l)
                                elif opt == 'roaipv6list':
					# FIXME: maxlength not yet supported
                                        l = config.get(section,opt)
                                        parse(roav6l, l)
                                elif opt == 'asid':
                                        a = config.getint(section,opt)
                                elif opt == 'subjkeyfile':
                                        val = config.get(section,opt)
                                        subjkeyfile = val.strip()
                                else:
                                        print 'Opt in config file not recognized: %s' % (opt)
                        try:
                                type,name=section.split('-')
                        except ValueError:
                                print 'Unrecognized type included in name of section in the .ini'
                                return
                        if type == 'C':
                                f = Factory(bluePrintName=name, ipv4List=ipv4,
                                            ipv6List=ipv6, asList=as_list,
                                            childSpec=child, serverName=server,
                                            breakAway=breakA, ttl=t,
                                            subjkeyfile=subjkeyfile)
                        elif type == 'M':
                                pass
                        elif type == 'CR':
                                pass
                        elif type == 'R':
                                f = ROA_Factory(bluePrintName=name, ipv4List=ipv4, \
                                                ipv6List=ipv6, asList=as_list, childSpec=child, \
                                                serverName=server, breakAway=breakA, ttl=t, \
                                                ROAipv4List =roav4l, ROAipv6List = roav6l,asid = a)  
                        else:
                                print 'Unrecognized type included in name of section in the .ini'
                                return 
                        #Add our bluePrintName to the factory dictionary
                        factory_dict[name]=f
                        
        except ValueError:
                print 'A ValueError occurred, check the syntax of your config file'
        except:
                print 'An error occurred'
                        

#Main create driver function used for creating directories and building them
#into a fully functioning repository
def create_driver(iana):

    #create our CA queue with no limit and place iana in it
    ca_queue = Queue(0)
    ca_queue.put(iana)
    #Add a flag to the queue track depth of repository
    ca_queue.put("FLAG - NEW LEVEL")
    #locals to keep track of where we are in creation
    repo_depth = 0
    repo_size = 1
    
    #check our conditionals
    while(not(ca_queue.empty()) and (MAX_DEPTH > repo_depth) and MAX_NODES > repo_size):
        
        ca_node = ca_queue.get()

        #Check if this is the start of a new level
        if ca_node == "FLAG - NEW LEVEL":
            #If we're at the end of the queue already then just break
            if ca_queue.empty()== True:
                break
            else:
                #Otherwise add the falg back into the queue to 
                #track for the next level
                ca_queue.put(ca_node)
                repo_depth+= 1
                #continue onto the next node in the queue
                continue

        #Create the directory for the objects we're about to store
        dir_path = REPO_PATH+"/"+ca_node.SIA_path+"/"
        if not os.path.exists(dir_path):
            os.system("mkdir -p "+ dir_path)


        child_list = []
        #Creates all child CA's and ROA's for a the CA ca_node
        child_list, repo_size = create_children(ca_node,repo_size)
        #crl_list
        new_crl = Crl(ca_node)
        ca_node.crl.append(new_crl)
        repo_size+=1
        #manifest_list
        #create an template factory for our ee needed in the manifest
        eeFactory = Factory("Manifest-EE", "inherit", "inherit", "inherit", ttl=ca_node.myFactory.ttl)
        new_manifest = Manifest(ca_node,eeFactory)
        ca_node.manifests.append(new_manifest)
        repo_size+=1

        
        #Add all of our children to the queue of CAs
        for child in child_list:
            if isinstance(child, CA_Object):
                ca_node.children.append(child)
                ca_queue.put(child)
            elif isinstance(child, Roa):
                ca_node.roas.append(child)
            else:
                print "Somehow got something besides CA or ROA in child list"

    print "Finished creation driver loop. repo_depth = "+ str(repo_depth)+\
            " repo_size = "+str(repo_size)
    print "MAX_REPO depth " + str(MAX_DEPTH)


def create_children(ca_node, repo_size):
    child_list = []
    print ca_node.bluePrintName
    list = FACTORIES[ca_node.bluePrintName].childSpec
    for ca_def in list:
        for n in range(0,ca_def[1]):
            if MAX_NODES > repo_size:
#	        try:
		    child = FACTORIES[ca_def[0]].create(ca_node)
		    child_list.append(child)
		    repo_size+=1
		    print "Child created. repo_size = %d" % repo_size
# 		except:
# 		    print "Child creation failed: type = %s" % ca_def[0]
            else:
                return (child_list, repo_size)  

    return (child_list, repo_size)


    
    
#
# A testing function to help determine if above classes
#   and functionality is correctly working. SPACED not TABBED function
#
def main():
        fileName = 'test.ini'
        if len(sys.argv) > 1:
            fileName = sys.argv[1]

        configuration_parser(FACTORIES,fileName)
        print FACTORIES
        #Declaring the initial resources we want IANA to have
        FACTORIES['IANA'].ipv4List = [IPNetwork('0/0')]
        FACTORIES['IANA'].ipv6List = [IPNetwork('0::/0')]
        FACTORIES['IANA'].asList = [ASRange("0-4294967295")] # (2^32-1)
        print FACTORIES['IANA'].ipv4List
        #House Keeping to clean up the old REPOSITORY
        #Should remove objects/keys,configs, and REPOSITORY
        os.system("rm -r "+OBJECT_PATH+"/*")
        
        iana = CA_Object(FACTORIES['IANA'])
        
        create_driver(iana)
        
#Fire off the test
if __name__ == '__main__':
    main()
   
