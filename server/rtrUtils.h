/* ***** BEGIN LICENSE BLOCK *****
 *
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 *
 * US government users are permitted unrestricted rights as
 * defined in the FAR.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  David Montana
 *
 * ***** END LICENSE BLOCK ***** */

/*
  $Id: query.c 857 2009-09-30 15:27:40Z dmontana $
*/

/************************
 * Some functions for handling RTR data
 ***********************/

#include "scmf.h"
#include "pdu.h"

extern uint getLastSerialNumber(scmcon *connect, scm *scmp);

/*
 * Argument: serialNum is the serial number relative to which want more recent
 * Note: Remember to free the array returned.
 * Note: Returns NULL if the original serial number is not in the database
 * Note: The results are in ascending order, from oldest to most recent
 */
extern uint* getMoreRecentSerialNums(scmcon *connect, scm *scmp,
									 uint serialNum);
