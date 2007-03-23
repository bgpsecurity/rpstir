/***********************************************************
 * X509 certificate verification routines              
 * 
 * int verify_cert(X509 *)
 *  input: pointer to X509 certificate
 *  output: ret = 1 if OK, ret < 0 if error (negative num
 *    indicates type of error)
 *  modifies: none
 *
 **********************************************************/ 

#include "verify_cert.h"

extern int fnno;  /* MCR */

/* statics */
static int checkit(X509_STORE *, X509 *, STACK_OF(X509) *, 
                   STACK_OF(X509) *, int , ENGINE *);



/******************************************************
 * verify_cert() is our main routine...               *
 *****************************************************/

int
verify_cert(X509 *c)
{

  STACK_OF(X509) *sk_trusted=NULL;
  STACK_OF(X509) *sk_untrusted=NULL;
  X509 *parent=NULL;
  X509_STORE *cert_ctx=NULL;
  X509_LOOKUP *lookup=NULL;
  X509_PURPOSE *xptmp=NULL;
  X509_VERIFY_PARAM *vpm=NULL;
  int ret, i, trust_anchor_flag, purpose;

  trust_anchor_flag = ret = i = purpose = 0;
  
  /****************************************************
   * basic boilerplate setup stuff that OpenSSL needs * 
   * us to do in order to use their internal check()  *
   * routine                                          * 
   ****************************************************/

  OpenSSL_add_all_algorithms();  /* don't forget this or else
                                    everthing builds fine but acts
                                    wonky!!! */
  ERR_load_crypto_strings();

  /* create X509 STORE */
  cert_ctx = X509_STORE_new();
  if (cert_ctx == NULL){
    int_error("could not create new X509_STORE");
  }

  /* set the verify callback */
  X509_STORE_set_verify_cb_func(cert_ctx, verify_callback);

  i = X509_PURPOSE_get_by_sname("any");
  xptmp = X509_PURPOSE_get0(i);
  purpose = X509_PURPOSE_get_id(xptmp);

  vpm = (X509_VERIFY_PARAM *)X509_VERIFY_PARAM_new();
  X509_VERIFY_PARAM_set_purpose(vpm, purpose);

  X509_STORE_set1_param(cert_ctx, vpm);

  lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());

  X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT); 
                                                              
  lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
                                                              
  X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);   
                                                              
  ERR_clear_error();                                          

  /****************************************************
   * END of basic setup                               *
   ****************************************************/



  /****************************************************/
  /* here comes the actual setup and iteration parts  */
  /*                                                  */
  /*  we will first creat a trusted and untrusted     */
  /*  STACK_OF(X509) stacks.                          */
  /*                                                  */
  /*  we call getParentCert on the cert passed in to  */
  /*  us. The returned cert is tested to see if it is */
  /*  a trust anchor. If it is, it is placed in the   */
  /*  trusted X509 stack and we break from the loop.  */
  /*                                                  */
  /*  If it is not a trust anchor, it is placed in    */
  /*  the untrusted X509 stack and we call for the    */
  /*  parent of the cert... etc. etc.                 */ 
  /*                                                  */
  /*  if we don't have a trust anchor, we will still  */
  /*  call the check() routine to let OpenSSL return  */
  /*  a "meaningfull" error. This might change in the */
  /*  future.                                         */                
  /****************************************************/

  sk_trusted = sk_X509_new_null();
  if (!sk_trusted) {
    int_error("failed to create trusted stack of X509");
  }

  sk_untrusted = sk_X509_new_null();
  if (!sk_untrusted) {
    int_error("failed to create untrusted stack of X509");
  }
 
  /****************************************************/
  /* using the variable 'i' as a counter is for our   */
  /* stub routines as we are using fixed files of     */
  /* {3,2,1,0}.pem.cer for input                      */
  /****************************************************/
  //  i = 1;
  
  i = fnno;			/* MCR */

  parent = getParentCert(c, i); 
  while (parent && (i >= 0) ) {
    ret = is_trust_anchor(parent, i);
    if (ret == 1) {
      sk_X509_push(sk_trusted, parent);
      trust_anchor_flag = 1;
      break;
    } else {
      sk_X509_push(sk_untrusted, parent);
    }
    i--;
    parent =  getParentCert(parent, i); 
  } 

#ifdef DEBUG
  if (!trust_anchor_flag) {
    fprintf(stderr, "no trust anchor - calling verify anyway\n");
  }
#endif

  ret = checkit(cert_ctx, c, sk_untrusted, sk_trusted, purpose, NULL);
  
  sk_X509_free(sk_trusted);
  sk_X509_free(sk_untrusted);

  X509_STORE_free(cert_ctx);
  X509_VERIFY_PARAM_free(vpm);

  return(ret);
}


/******************************************************/
/* void handle_error(const char *, int, const char *) */
/*   error handler. int_error is a simple macro that  */
/*   calls handle_error with __FILE__, __LINE__, and  */
/*   error_msg.                                       */
/******************************************************/
void
handle_error(const char *file, int lineno, const char *msg)
{ 
  fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
  exit(-1);
} 
  
/******************************************************
 * int verify_callback(int, X509_STORE_CTX *)         *
 *   a trivial callback that is setup via             *
 *   X509_STORE_set_verify_cb_function(). We could    *
 *   eventually have this map to an int return that   *
 *   is meaningful for our program rather than OpenSSL*
 *   meaning-specific.                                *
 *****************************************************/
int 
verify_callback(int ok, X509_STORE_CTX *store)
{
  if (!ok) {
    fprintf(stderr, "Error: %s\n", X509_verify_cert_error_string(store->error));
  }
  return(ok);
} 


/******************************************************
 * static int checkit(cert_ctx, x, sk_untrusted,      *
 *                     sk_trusted, purpose, NULL)     *
 *   This is the routine that actually calls          *
 *     X509_verify_cert(). Prior to calling the final *
 *     verify function it performs the following      *
 *     steps(+):                                      *
 *                                                    *
 *     creates an X509_STORE_CTX                      *
 *     sets the flags to 0                            *
 *     initializes the CTX with the X509_STORE,       *
 *         X509 cert being checked, and the stack     *
 *         of untrusted X509 certs                    *
 *     sets the trusted stack of X509 certs in the CTX* 
 *     sets the purpose in the CTX (which we had      *
 *       set outside of this function to the OpenSSL  *
 *       definition of "any")                         *
 *     calls X509_verify_cert                         *
 *                                                    *
 *  This function is modified from check() in         *
 *  apps/verify.c of the OpenSSL source               *
 ******************************************************/

static int checkit(X509_STORE *ctx, X509 *x, STACK_OF(X509) *uchain, 
                 STACK_OF(X509) *tchain, int purpose, ENGINE *e)
{
  int i=0,ret=0;
  X509_STORE_CTX *csc;

  csc = X509_STORE_CTX_new();
  if (csc == NULL) {
    fprintf(stderr, "failed on X509_STORE_CTX_new\n");
    goto end;
  }

  X509_STORE_set_flags(ctx, 0);
  if(!X509_STORE_CTX_init(csc,ctx,x,uchain)) {
    fprintf(stderr, "failed on X509_STORE_CTX_init\n");
    goto end;
  }

  if(tchain) 
    X509_STORE_CTX_trusted_stack(csc, tchain);

  if(purpose >= 0) 
    X509_STORE_CTX_set_purpose(csc, purpose);

  i=X509_verify_cert(csc);

  X509_STORE_CTX_free(csc);

  ret=0;
end:
  if (i) {                                             
    fprintf(stdout,"OK\n");                       
    ret=1;
  } else {
    fprintf(stdout, "error...\n");
  }

  return(ret);                                          
}                                                     
