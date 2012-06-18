/*
 * File: create_cert.h Contents: Header file for creating testbed certificates
 * Created: Author: Karen Sirois
 * 
 * Remarks:
 * 
 * ****************************************************************************
 */
#ifndef _CREATE_CERT_H
#define _CREATE_CERT_H

#include "create_object.h"

extern struct object_field cert_field_table[];
extern struct object_field *get_cert_field_table(
    void);

#endif                          /* _CREATE_CERT_H */
