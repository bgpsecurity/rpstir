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
#include <util/cryptlib_compat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "usage.h"
#include "socket_stuff.h"
#include "parse.h"
#include "sig_handler.h"
#include "rpki-asn1/roa.h"
#include "rpki/cms/roa_utils.h"
#include "rpki-asn1/certificate.h"
#include "rpki/err.h"
#include "util/logging.h"
#include "util/stringutils.h"

#define INFO_FLAG 0x1
#define WARNING_FLAG 0x2
#define ERROR_FLAG 0x4

#define TRUE 1
#define FALSE 0

struct write_port *global_wport;

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(A) ((void)A)
#endif

#endif
