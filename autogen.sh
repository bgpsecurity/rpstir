#!/bin/sh -e 
# /* ***** BEGIN LICENSE BLOCK *****
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
# * Contributor(s):  Brenton Kohler(bkohler@bbn.com)
# *
# * ***** END LICENSE BLOCK ***** */
#This builds all necessary Makefile.in's and other necessary files and then generates
# the configure script.
autoreconf --force --install --verbose
