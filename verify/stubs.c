#include "stubs.h"

/******************************************************/
/* STUB STUB STUB STUB STUB STUB STUB STUB STUB STUB  */
/*                                                    */
/* int is_trust_anchor(X509 *, int)                   */
/*   input: pointer to X509 cert, int for stub        */
/*          purposes                                  */
/*   output: integer 1 for TRUE 0 for FALSE           */
/*   modifies: none                                   */
/*   notes: this is a stub routine for testing the    */
/*          verify_cert function                      */
/*                                                    */
/* STUB STUB STUB STUB STUB STUB STUB STUB STUB STUB  */
/******************************************************/
int
is_trust_anchor(X509 *certPtr, int val)
{
  if (val == 0)
    return(1);
  else
    return(0);
}

/******************************************************/
/* STUB STUB STUB STUB STUB STUB STUB STUB STUB STUB  */
/*                                                    */
/* X509 * getParentCert(X509 *, int )                 */
/*   input: pointer to X509 cert, int for stub        */
/*          purposes (tells which cert to return)     */
/*   output: pointer to parent cert or NULL           */
/*   modified: none                                   */
/*   notes: stub routine used in retrieving test      */
/*          values for populating stacks that will    */
/*          ultimately be used in check_cert.         */
/*                                                    */
/* STUB STUB STUB STUB STUB STUB STUB STUB STUB STUB  */
/******************************************************/
X509 *
getParentCert(X509 *certPtr, int val)
{
  FILE *cert_fp;
  char file[32];
  X509 *x=NULL;

  memset((void *)file, '\0', sizeof(file));

  snprintf(file, sizeof(file) -1, "%d.cer.pem", val);

  cert_fp = fopen(file, "r");
  if (cert_fp == NULL) {
    fprintf(stderr, "could not open [%s] - getParentCert returning NULL\n",
            file);
    return(NULL);
  }

  x = PEM_read_X509(cert_fp, NULL, NULL, NULL);
  if (!x) {
    fprintf(stderr, "Error reading X509 cert from [%s] - returning NULL\n",
            file);
    return(NULL);
  } else {
    return(x);
  }

  fclose(cert_fp);
}


