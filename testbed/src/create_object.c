
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include "cryptlib.h"
#include "certificate.h"
#include "roa.h"
#include "keyfile.h"
#include "casn.h"
#include "asn.h"
#include <time.h>
#include "create_object.h"
#include "create_cert.h"
#include "create_crl.h"
#include "create_manifest.h"
#include "create_roa.h"
#include "obj_err.h"

/* function declrations */
extern int sign_object(int type,struct casn *object, char *keyname);
extern int create_cert(struct object_field *table);
extern int create_crl(struct object_field *table);
extern int create_roa(struct object_field *table);
extern int create_manifest(struct object_field *table);
extern int fieldInTable(char *field, int field_len, struct object_field *tbl);
extern char *stripws(char *str);
extern int validate_table(struct object_field *table, char *errstr, int len);
void print_table(struct object_field *table);
char parse_errstr[1024];
char validate_errstr[1024];
const char *templateFile = NULL;

// see obj_err.h for error codes
char *msgs [] =
  {
    "Finished %s created\n", // SUCCESS
    "Error parsing input arguments: %s \n", // INPUT_ARG_ERR
    "Error missing the following fields: %s \n", // MISSING_FIELDS
    "Error opening file %s\n", // FILE_OPEN_ERR
    "Error reading file %s\n", // FILE_READ_ERR
    "Error writing to File %s\n", // FILE_WRITE_ERR
    "Missing Certificate type (EE or CA) - aborting\n", //MISSING_CERT_TYPE
    "Missing Serial Number - aborting\n", //MISSING_SERIAL_NUMBER

    "Unsupported object type %s\n", // 2
    "Couldn't open %s\n",
    "Can't translate %s.  Try again\n",      
    "Usage: subjectname startdelta enddelta\n [b(ad signature) | e(xplicit IP) | n(either)]\n",
    "Issuer cert has no %s extension\n",              
    "Signing failed in %s\n",
    "Error opening %s\n",                
    "Error reading IP Address Family\n",
    "Error padding prefix %s. Try again\n",
    "Invalid time delta type: %s\n",
    "Invalid cert name %s\n",          
    "Error creating %s extension\n",
    "Error in CA %s extension\n",     
    "Invalid parameter %s\n",
    "Directory Error %s\n",           
    "Error opening keyfile %s\n",     
    };

void warn(int err, char *param)
{
  fprintf(stderr, msgs[err], param);
}

static void fatal(int err, char *param)
  {
  warn(err, param);
  exit(err);
  }


/* parse_config
 * Parse the config file into the fields structure.
 * Inputs: configfile
 * Output: the table of name/value pairs for the object being created
 *         is filled in with values from the arg list.
 * Returns 0 Success
 *         1 if error
 *
 * For every name/value pair in the config file, search for the name in 
 * the field_table (all possible argument names) and fill the 
 * value in the table. 
 */
int parse_config(char *configfile, struct object_field *tbl)
{
  int  n, err = 0;
  char *name, *value;
  int name_len;
  FILE *fp; 
  char *buf;
  int flen;
  struct stat stbuf;

  memset(parse_errstr,0, sizeof(parse_errstr));

  if (stat(configfile,&stbuf) != 0)
    {
      fprintf(stderr, "Error getting file size %s\n", configfile);
      return 1;
    }

  flen =  stbuf.st_size;
  if ( (buf = calloc(flen, sizeof(char))) == NULL)
    {
      fprintf(stderr, "Memory Error\n");
      return 1;
    }

  // Open the config file
  fp = fopen(configfile, "r");
  if (fp == NULL)
    {
      fprintf(stderr, "Error Opening Config File %s\n", configfile);
      return 1;
    }

  // read each line and process
  while (fgets(buf, flen, fp) != NULL)
    { 
      name = buf;
      while(isspace((int)(unsigned char)*name)) name++;
      if ( (strncmp(name,";", 1) == 0) || strlen(buf) <= 0)
	continue;

      value = strchr(buf,'=');      
      if ( (value == NULL) || (strlen(value+1) <=0)) {
	fprintf(stderr,"Warning: blank value (line: %s)\n", buf);
	continue;
      }

      name_len = value - name;      
      if ((n = fieldInTable(name, name_len, tbl)) >= 0) 
	tbl[n].value = stripQuotes(stripws(++value));
      else
	{
	  if (err != 0) // not first error, add comma
	    strcat(parse_errstr,", ");
	  strcat(parse_errstr,name);
	  err = 1;
	}
    }
  return err;
}


/* parse_args
 * Parse the arguments from the command line into the fields structure.
 * Inputs: argc, argv
 * Output: the table of name/value pairs for the object being created
 *         is filled in with values from the arg list.
 * Returns 0 Success
 *         1 if error
 *
 * For every name/value pair in the arg list, search for the name in 
 * the field_table (all possible argument names) and fill the 
 * value in the table. 
 * Note: An error message is printed for every argument that is not
 *       in the fields table. All arguments are parsed.
 * 
 */
int parse_args(int argc, char **argv, int index, struct object_field *tbl)
{
  int i, n, err = 0;
  char *cur, *name, *value;
  int name_len;
  
  memset(parse_errstr,0, sizeof(parse_errstr));

  // for every argument in the list, update the table with the new value
  // first arg is program name and second is object type. The remainder are
  // object fields

  for (i = index; i < argc; i++)
    {
      cur = argv[i];
      name = cur;
      value = strchr(cur,'=');
      if (value == NULL)
	{
	  if (err != 0) // not first error, add comma
	    strcat(parse_errstr,", ");

	  strcat(parse_errstr,cur);
	  err = 1;
	}
      else
	{ // find the right place in the table to put the value
	  name_len = value - name;
	  if ((n = fieldInTable(name, name_len, tbl)) >= 0) 
	    tbl[n].value = stripws(++value);
	  else
	    {
	      if (err != 0) // not first error, add comma
		strcat(parse_errstr,", ");

	      strcat(parse_errstr,name);
	      err = 1;
	    }
	}
    }
  // done
#ifdef DEBUG
  if (err == 0)	print_table(tbl);
#endif
  return err;
}


// print usage to stdout for the user
void printUsage(char **argv)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "        %s OBJECT_TYPE arg1=value arg2=value arg3=value\n", argv[0]);
  fprintf(stderr, "\n");
  fprintf(stderr, "where OBJECT_TYPE is one of the following: \n");
  fprintf(stderr, "            (CERT, CRL, ROA or MANIFEST)\n"); 
  fprintf(stderr, "and argument/value pairs are based upon the object type\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options:\n");
  fprintf(stderr, "\t-f\tread config file for additional argument/value pairs (cmd line takes precedence)\n");
  fprintf(stderr, "\t-t\tuse specified file template rather than the default\n");
  fprintf(stderr, "\t-h\tprint this usage\n");
  exit(0);
}

/* create_object
 * parse the object fields from the command line and
 * call the appropriate object creator with a table of
 * fields filled in.
 */
int main(int argc, char **argv)
{

  int ret = 0;
  int parse_err = 0;
  int index = 1;
  int c;
  char *obj_type;
  char *configFile = NULL;
  extern char *optarg;
  struct object_field *table;


  // parse options
  while ((c = getopt (argc, argv, "hf:t:")) != -1)
    {
      switch (c)
	{
	case 'h':
	  printUsage(argv);
	  break;

	case 'f':
	  configFile=optarg;
	  break;

	case 't':
	  templateFile=optarg;
	  break;

	case '?':
	  printUsage(argv);
	  break;

	default:
	  fprintf(stderr,"Illegal Option\n");
	  printUsage(argv);
	  break;
	}
    }

  index = optind;		// remaining arguments
  if (configFile == NULL)
      fprintf(stdout, "No Config file\n");

  if (index >= argc)
    fatal(INPUT_ARG_ERR, "No Object Type");
  else
    obj_type = argv[index++];

  if (strncasecmp(obj_type,"CERT", strlen("CERT")) == 0)
    {
      table = get_cert_field_table();
      if (configFile != NULL)
	if (parse_config(configFile, table) != 0)
	{
	  warn(INPUT_ARG_ERR, parse_errstr);
	  parse_err = 1;
	}

      // parse and validate arguments, exit if either or both fail
      if (parse_args(argc, argv, index, table) != 0)
	{
	  warn(INPUT_ARG_ERR, parse_errstr);
	  parse_err = 1;
	}
      if (validate_table(table, validate_errstr,sizeof(validate_errstr)) != 0)
	fatal(MISSING_FIELDS, validate_errstr);

      // if no validation error but we did have a parse err - exit
      if (parse_err)
	exit(INPUT_ARG_ERR);

      ret = create_cert(table);
      //fprintf(stdout,"return from creating certificate %d\n", ret);
    }
  else if (strncasecmp(obj_type,"CRL", strlen("CRL")) == 0)
    {
      table = get_crl_field_table();
      if (configFile != NULL)
	if (parse_config(configFile, table) != 0)
	{
	  warn(INPUT_ARG_ERR, parse_errstr);
	  parse_err = 1;
	}

      if (parse_args(argc, argv, index, table) != 0)
	{
	  warn(INPUT_ARG_ERR, parse_errstr);
	  parse_err = 1;
	}
      if (validate_table(table, validate_errstr,sizeof(validate_errstr)) != 0)
	fatal(MISSING_FIELDS, validate_errstr);

      // if no validation error but we did have a parse err - exit
      if (parse_err)
	exit(INPUT_ARG_ERR);

      ret = create_crl(table);
    }
  else if (strncasecmp(obj_type,"ROA", strlen("ROA")) == 0)
    {
      table = get_roa_field_table();
      if (configFile != NULL)
	if (parse_config(configFile, table) != 0)
	{
	  warn(INPUT_ARG_ERR, parse_errstr);
	  parse_err = 1;
	}

      if (parse_args(argc, argv,index, table) != 0)
	fatal(INPUT_ARG_ERR, parse_errstr);
      
      if (validate_table(table, validate_errstr,sizeof(validate_errstr)) != 0)
	fatal(MISSING_FIELDS, validate_errstr);
      ret = create_roa(table);
    }
   else if (strncasecmp(obj_type,"MANIFEST", strlen("MANIFEST")) == 0)
     {
      table = get_man_field_table();
      if (configFile != NULL)
	if (parse_config(configFile, table) != 0)
	{
	  warn(INPUT_ARG_ERR, parse_errstr);
	  parse_err = 1;
	}
      
      // parse arguments and validate table
      if (parse_args(argc, argv,index, table) != 0)
	warn(INPUT_ARG_ERR, parse_errstr);
      
      if (validate_table(table, validate_errstr,sizeof(validate_errstr)) != 0)
	fatal(MISSING_FIELDS, validate_errstr);
      ret = create_manifest(table);
     }
  else
       fatal(INPUT_ARG_ERR, argv[1]);

  exit(ret);
}

