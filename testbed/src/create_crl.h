/*
File:     create_crl.h
Contents: Header file for creating testbed crls
Created:
Author:   Karen Sirois

Remarks:

 ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 1995-2007.  All Rights Reserved.
 *
 * Contributor(s):  Karen Sirois
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/
#ifndef _CREATE_CRL_H
#define _CREATE_CRL_H

#include "create_object.h"

extern struct object_field crl_field_table[];
extern struct object_field *get_crl_field_table(void);

#endif /* _CREATE_CRL_H */
