/******************************************************
 * signal handling routines                           *
 *                                                    *
 * Here we setup a trivial signal handler function    *
 * that will inform the recipient specified in the    *
 * write_port structure setup elsewhere (and then     *
 * referenced via a global pointer to the structure)  *
 * that a signal was caught. It will then send the    *
 * endMessage and exit.                               *
 *                                                    *
 * These are here more for templates should someone   *
 * want to introduce more elaborate handling of       *
 * signals.                                           *
 *****************************************************/
#include "sig_handler.h"

extern struct write_port *global_wport;

void
sig_handler(int sig)
{
  char *outStr;
  char errorStr[128];
  unsigned int retlen;

  retlen = 0;
 
  memset(errorStr, '\0', sizeof(errorStr));

  if (sig == SIGINT) {
    snprintf(errorStr, sizeof(errorStr), "SIGINT caught\r\n");
    outStr = makeFatalStr(errorStr, strlen(errorStr), &retlen);
    if (outStr) {
      outputMsg(global_wport, outStr, retlen);
      free(outStr);
    }
    retlen = 0;
    outStr = makeEndStr(&retlen);
    if (outStr) {
      outputMsg(global_wport, outStr, retlen);
      free(outStr);
    }
    close(global_wport->out_desc);
    exit(FALSE);
  } else if (sig == SIGQUIT) {
    snprintf(errorStr, sizeof(errorStr), "SIGQUIT caught\r\n");
    outStr = makeFatalStr(errorStr, strlen(errorStr), &retlen);
    if (outStr) {
      outputMsg(global_wport, outStr, retlen);
      free(outStr);
    }
    retlen = 0;
    outStr = makeEndStr(&retlen);
    if (outStr) {
      outputMsg(global_wport, outStr, retlen);
      free(outStr);
    }
    close(global_wport->out_desc);
    exit(FALSE);
  } else if (sig == SIGTERM) {
    snprintf(errorStr, sizeof(errorStr), "SIGTERM caught\r\n");
    outStr = makeFatalStr(errorStr, strlen(errorStr), &retlen);
    if (outStr) {
      outputMsg(global_wport, outStr, retlen);
      free(outStr);
    }
    retlen = 0;
    outStr = makeEndStr(&retlen);
    if (outStr) {
      outputMsg(global_wport, outStr, retlen);
      free(outStr);
    }
    close(global_wport->out_desc);
    exit(FALSE);
  }
}

int
setup_sig_catchers(void)
{
  struct sigaction sa;

  /* initialize sigaction structure */
  sa.sa_handler = sig_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  /* map the signals to the handler referenced in sigaction struct */
  if (sigaction(SIGINT, &sa, NULL) != 0) {
    return(FALSE);
  }
  if (sigaction(SIGQUIT, &sa, NULL) != 0) {
    return(FALSE);
  }
  if (sigaction(SIGTERM, &sa, NULL) != 0) {
    return(FALSE);
  }
  return(TRUE);
}
