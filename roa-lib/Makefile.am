#
# Makefile for roa libs
#
# $Id: Makefile 527 2008-06-17 15:02:18Z csmall $
#
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Version 3.0-beta
#  
#  US government users are permitted unrestricted rights as
#  defined in the FAR.  
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# 
#  Contributor(s):  Brenton Kohler
# 
# ***** END LICENSE BLOCK *****

AM_CFLAGS = -I../proto -I../cg/asn -I../cg/asn_gen -I../cg/casn \
	-g -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations -DANYSKI

noinst_LIBRARIES = libroa.a

libroa_a_SOURCES = roa_validate.c roa_utils.h roa_create.c roa_general.c signCMS.c roa_serialize.c
