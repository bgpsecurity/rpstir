#ifndef __MAIN_H
#define __MAIN_H

/*
 * $Id$ 
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <cryptlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "usage.h"
#include "socket_stuff.h"
#include "parse.h"
#include "sig_handler.h"
#include "roa.h"
#include "roa_utils.h"
#include "certificate.h"
#include "err.h"
#include "logutils.h"
#include "stringutils.h"

#define INFO_FLAG 0x1
#define WARNING_FLAG 0x2
#define ERROR_FLAG 0x4

#define TRUE 1
#define FALSE 0

struct write_port *global_wport;

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(A) { void *craig = (void *)(A); craig++; }
#endif

#endif