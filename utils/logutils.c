/*
  Logging utilities

  $Id$
*/

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.
 * All Rights Reserved.
 *
 * Contributor(s):  Andrew Chi
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include "logutils.h"

/* globals */
static FILE *log_fp = NULL;
static int log_filethresh = LOG_DEBUG;
static int log_stderrthresh = LOG_DEBUG;
static const char *log_facility = "none"; /* rcli, rsync_aur, chaser */

/* function prototypes */
static const char *log_level2string(int priority);
static void
log_msg_generic(FILE *fp, struct tm *timestamp, const char *facility,
		int priority, const char *format, ...);


/*
 * Initialize logging system.  Open "logfile" for append, set the
 * facility (i.e. component name), and set the logging verbosity to
 * file and to standard error.
 *
 * Returns 0 on success.  On error, returns -1 and sets errno with a
 * system-wide value indicating the cause of the error.
 *
 * IMPORTANT: each executable can have at most one logging system
 * initialized.  If you call log_init() from main() only, then you
 * should be fine.
 */
int log_init(const char *logfile, const char *facility,
	     int file_loglevel, int stderr_loglevel)
{
  if (!logfile || !facility) {
    errno = EINVAL;		/* Invalid argument */
    return -1;
  }
  
  log_fp = fopen(logfile, "a");
  if (!log_fp)
    return -1;			/* errno set by fopen() */

  log_facility = strdup(facility);
  if (!log_facility) {
    log_facility = "none";
    fclose(log_fp);
    log_fp = NULL;
    errno = ENOMEM;
    return -1;
  }
  
  log_filethresh = file_loglevel;
  log_stderrthresh = stderr_loglevel;

  log_msg(LOG_MAINT,
	  "Logging initialized: filelevel=%d, stderrlevel=%d, file=%s",
	  log_filethresh,
	  log_stderrthresh,
	  logfile);

  return 0;
}


/*
 * Log a message with a given priority (e.g. LOG_WARNING), using
 * printf-style parameters.
 */
void log_msg(int priority, const char *format, ...)
{
  va_list args;
  time_t now_sec;
  struct tm now;

  if (!log_fp)			/* logging not initialized */
    return;

  if (!format)
    return;

  /* build timestamp */
  now_sec = time(NULL);
  (void)gmtime_r(&now_sec, &now); /* fails only after year exceeds MAX_INT */

  /* write message to logfile */
  if (priority == LOG_MAINT || priority <= log_filethresh) {
    va_start(args, format);
    log_msg_generic(log_fp, &now, log_facility, priority, format, args);
    va_end(args);
  }

  /* write message to stderr */
  if (priority <= log_stderrthresh) {
    va_start(args, format);
    log_msg_generic(stderr, &now, log_facility, priority, format, args);
    va_end(args);
  }
  
  return;
}


/*
 * Ensure that all buffered log messages are flushed out to disk
 * and/or stderr.
 */
void log_flush(void)
{
  if (!log_fp)			/* logging not initialized */
    return;
  
  fflush(log_fp);
  fflush(stderr);
}


/*
 * Close the log file and clear the logging state.
 */
void log_close(void)
{
  int ret;

  if (!log_fp)
    return;
  
  log_msg(LOG_MAINT, "Logging closed");
  
  ret = fclose(log_fp);
  if (ret != 0)
    perror("log_close");

  log_fp = NULL;
  log_facility = "none";
}


const char *log_level2string(int priority)
{
  if (priority == 3)
    return "Error";
  else if (priority == 4)
    return "Warning";
  else if (priority == 5)
    return "Notice";
  else if (priority == 6)
    return "Info";
  else if (priority == 7)
    return "Debug";
  else
    return "-------";
}


void log_msg_generic(FILE *fp, struct tm *timestamp, const char *facility,
		     int priority, const char *format, ...)
{
  va_list args;
  
  if (!fp || !timestamp || !format)
    return;

  /* timestamp */
  fprintf(fp, "UTC %4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d | ",
	  timestamp->tm_year + 1990,
	  timestamp->tm_mon + 1,
	  timestamp->tm_mday,
	  timestamp->tm_hour,
	  timestamp->tm_min,
	  timestamp->tm_sec);

  /* facility */
  fprintf(fp, "%-10s | ", facility);

  /* priority */
  fprintf(fp, "%-7s | ", log_level2string(priority));

  /* custom message */
  va_start(args, format);
  vfprintf(fp, format, args);
  va_end(args);
  fprintf(fp, "\n");
}
