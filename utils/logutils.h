/*
  Logging utilities

  $Id$
*/


#ifndef _UTILS_LOGUTILS_H
#define _UTILS_LOGUTILS_H


#include "macros.h"

/* These definitions follow conventional meaning and numeric value of
   kernel loglevels defined in linux/kernel.h */
#define LOG_ERR     3		/* error conditions */
#define LOG_WARNING 4		/* warning conditions */
#define LOG_NOTICE  5		/* normal but significant condition */
#define LOG_INFO    6		/* informational */
#define LOG_DEBUG   7		/* debug-level messages */
#define LOG_MAINT   100		/* logfile maintenance messages */

/* Logging interface */
int log_init(const char *logfile, const char *facility,
	     int file_loglevel, int stderr_loglevel);
void log_msg(int priority, const char *format, ...) WARN_PRINTF(2,3);
void log_flush(void);
void log_close(void);


#endif
