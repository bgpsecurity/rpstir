#include "usage.h"

/*****************************************************/
/* void usage(const char *)                          */
/*                                                   */
/* Simple little usage output for stub_main.         */
/* The correct usage of the test program is:         */
/*   ./progname cert_file                            */
/*                                                   */
/* Where cert file is 3.cer.pem                      */
/*****************************************************/

void
myusage(const char *progname)
{
  char *prog;                                                 
                                                              
  prog = strrchr(progname, '/');                              
  if (!prog)                                                  
    prog = (char *)progname;                                  
  else                                                        
    prog++;                                                   
                                                              
  fprintf(stderr, "Usage: %s certfile\n",  prog);                                            
  exit(1);                                                    
}                                                             

