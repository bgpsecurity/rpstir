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

MAX_DEPTH = 1
MAX_NODES = 10
FACTORIES = {}

#
# Parses the val as a string like AFRINIC,1%APNIC,2%RIPE,2...
# Stores result as a tuple in the list toMode
#
def parse(toMod, val):
        # parse the string like AFRINIC,1%APNIC,2%RIPE,2...
        tup = val.split('%')
        for i in tup:
                try:
                        #split the individual groups
                        one,two=i.split(',')
                        x = (one,int(two))
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
                        as         = []
                        
                        for opt in options:
                                if opt == 'childspec':
                                        val = config.get(section,opt)
                                        # parse the string like AFRINIC,1%APNIC,2%RIPE,2...
                                        parse(child,val)
                                elif opt == 'ipv4list':
                                        l = config.get(section,opt)
                                        parse(ipv4,l)
                                elif opt == 'ipv6list':
                                        l = config.get(section,opt)
                                        parse(ipv6,l)
                                elif opt == 'aslist':
                                        l = config.get(section,opt)
                                        parse(as,l)
                                elif opt == 'servername':
                                        server = config.get(section,opt)
                                elif opt == 'breakaway':
                                        breakA = config.get(section,opt)
                                elif opt == 'ttl':
                                        t = config.getint(section,opt)
                                elif opt == 'max_depth':
                                        MAX_DEPTH=config.getint(section,opt)
                                elif opt == 'max_nodes':
                                        MAX_OPTS=config.getint(section,opt)
                                else:
                                        print 'Opt in config file not recognized: %s' % (opt)

                                f = Factory(bluePrintName=section, ipv4List=ipv4,
                                            ipv6List=ipv6, asList=as,
                                            childSpec=child, serverName=server,
                                            breakAway=breakA, ttl=t)
                
                                factory_dict[section]=f
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
	#locals to keep track of where we are in creation
	repo_depth = 0
	repo_size = 1
	
	#check our conditionals
	while(not(ca_queue.empty()) and MAX_DEPTH > repo_depth and MAX_NODES > repo_size):
		ca_node = ca_queue.get()
		child_list = create_children(ca_node)
		ca_node.children = child_list
		#roa_list
		#crl_list
		#manifest_list
		
		#Add all of our children to the queue of CAs
		for child in child_list:
			ca_queue.put(child)



def create_children(ca_node):
	child_list = []
	list = FACTORIES[ca_node.bluePrintName].childSpec
	for ca_def in list:
		for n in range(0,ca_def[1]):
			child_list.append(factories[ca_def[0]].create(ca_node))
	return child_list
	
	
configuration_parser(FACTORIES)


