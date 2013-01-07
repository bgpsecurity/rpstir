/*
 * File: obj_err.h Contents: error codes and strings for object creation
 * Created: Author: Karen Sirois
 * 
 * Remarks:
 * 
 * ****************************************************************************
 */
#ifndef _OBJ_ERR_H
#define _OBJ_ERR_H


enum OBJ_ERRORS {
    SUCCESS = 0,
    INPUT_ARG_ERR,
    MISSING_FIELDS,
    FILE_OPEN_ERR,
    FILE_READ_ERR,
    FILE_WRITE_ERR,
    MISSING_CERT_TYPE,
    MISSING_SERIAL_NUMBER,
};

extern void warn(
    int code,
    const char *arg);

#endif                          /* _OBJ_ERR_H */
