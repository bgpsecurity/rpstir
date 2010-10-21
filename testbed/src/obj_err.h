/*
File:     obj_err.h
Contents: error codes and strings for object creation
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
#ifndef _OBJ_ERR_H
#define _OBJ_ERR_H


enum OBJ_ERRORS
{
  SUCCESS = 0,
  INPUT_ARG_ERR,
  MISSING_FIELDS,
  FILE_OPEN_ERR,
  FILE_READ_ERR,   
  FILE_WRITE_ERR,
  MISSING_CERT_TYPE,
  MISSING_SERIAL_NUMBER,
};

extern void warn(int code, char *arg);

#endif /* _OBJ_ERR_H */
