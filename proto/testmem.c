/*
  $Id: rcli.c 189 2007-05-09 18:14:22Z dmontana $
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>
#include <netdb.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include "err.h"

int main(void)
{
   char *fname = "oop.cer.pem";
   char *fullname = "/home/mreynolds/apki/trunk/proto/oop.cer.pem";
   int   typ = infer_filetype(fullname);
   int   sta = 0;
   int   x509sta = 0;
   BIO  *bcert = NULL;
   X509 *x = NULL;
   cert_fields *cf;

   cf = cert2fields(fname, fullname, typ, &x, &sta, &x509sta);
   (void)printf("cf = 0x%x x = 0x%x\n", (unsigned int)cf, (unsigned int)x);
   freecf(cf);
#ifdef NOTDEF
   bcert = BIO_new(BIO_s_file());
   (void)printf("BIO = %x\n", (unsigned int)bcert);
   if ( bcert == NULL ) return(-1);
   x509sta = BIO_read_filename(bcert, fullname);
   if ( x509sta <= 0 )
     {
       BIO_free(bcert);
       return(-2);
     }
   if ( typ < OT_PEM_OFFSET )
     x = d2i_X509_bio(bcert, NULL);
   else
     x = PEM_read_bio_X509_AUX(bcert, NULL, NULL, NULL);
   (void)printf("x = 0x%x\n", (unsigned int)x);
   BIO_free(bcert);
#endif
   X509_free(x);
   return(0);
}
