/*
 * File: create_crl.h Contents: Header file for creating testbed crls Created:
 * Author: Karen Sirois
 * 
 * Remarks:
 * 
 * ****************************************************************************
 */
#ifndef _CREATE_CRL_H
#define _CREATE_CRL_H

#include "create_object.h"

extern struct object_field crl_field_table[];
extern struct object_field *get_crl_field_table(
    void);

#endif                          /* _CREATE_CRL_H */
