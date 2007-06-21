#include "main.h"

/*
  $Id$
*/

/*****************************************************/
/* void usage(const char *)                          */
/*                                                   */
/*****************************************************/

void
usage(const char *progname)
{
  char *prog;                                                 
                                                              
  prog = strrchr(progname, '/');                              
  if (!prog)                                                  
    prog = (char *)progname;                                  
  else                                                        
    prog++;                                                   
                                                              
  fprintf(stderr, "%s Usage:\n",  prog); 
  fprintf(stderr, "\t-t portno\tconnect to TCP portno\n");
  fprintf(stderr, "\t-u portno\tconnect to UDP portno\n");
  fprintf(stderr, "\t-f filename\trsync logfile to read\n");
  fprintf(stderr, "\t-d dirname\trepository directory\n");
  fprintf(stderr, "\t-n         \tdo nothing - print what hould have been done\n");
  fprintf(stderr, "\t-w         \tcreate warning message(s)\n");
  fprintf(stderr, "\t-e         \tcreate error message(s)\n");
  fprintf(stderr, "\t-i         \tcreate informational message(s)\n");
  fprintf(stderr, "\t-s         \tsynchronize with rcli at the end\n");
  fprintf(stderr, "\t-h         \tthis help listing\n");
 
  exit(1);                                                    
}                                                             

