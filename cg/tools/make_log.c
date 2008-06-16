#include <stdio.h>

/* converts a list of file names to a log file to go in LOGS. 
   It is  straight filter*/

char buf[512];

int main( int argc, char **argv)
  {
  fprintf(stdout, "cd+++++++ ./\n");
  while (fgets(buf, 512, stdin))
    {
    fprintf(stdout, ">f+++++++ %s", buf);
    }
  return 0;
  }  
