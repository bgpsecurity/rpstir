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
from Queue import Queue	
from rpkirepo import *

MAX_DEPTH = 1
MAX_NODES = 10
FACTORIES = {}



def configuration_parser(factory_dict):
	pass


#Main create driver function used for creating directories and building them
#into a fully functioning repository
def create_driver(iana):
	ca_queue = Queue(0)
	ca_queue.put(iana)
	
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
		ca_queue.append(child_list)



def create_children(ca_node):
	child_list = []
	list = FACTORIES[ca_node.bluePrintName].childSpec
	for ca_def in list:
		for n in range(0,ca_def[1]):
			child_list.append(factories[ca_def[0]].create(ca_node))
	return child_list
	
	
configuration_parser(FACTORIES)
