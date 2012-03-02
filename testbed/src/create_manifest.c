#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include "cryptlib.h"
#include "../asn/certificate.h"
#include "../asn/roa.h"
#include <keyfile.h>
#include <casn.h>
#include <asn.h>
#include <time.h>
#include "create_object.h"
#include "obj_err.h"
//#include "create_utils.h"
#include <sys/types.h>
#include <dirent.h>
#include "cryptlib.h"

/**
 *
 * This file is designed to provide functions to create a manifest
 *  from a template. 
 *
 **/
void print_table(struct object_field *table);
int write_EEcert(void* my_var, void* value);
int write_EEkey(void* my_var, void* value);
char *man_template = "../templates/M.man";

/**
 * Write the unique identifier for this manifest number
 *
 *
 **/
int write_manNum(void* man, void* value)
{
  //first I cast the generic parameters, then I grab the manifest part of the 
  // CMS object, then I parse the value parameter into a long and then I write 
  // it into the struct. 
  struct ROA* roa = man;
  struct Manifest *manp = &roa->content.signedData.encapContentInfo.eContent.manifest;
  long manNum = strtol(((char*)value), NULL, 0);
  write_casn_num( &manp->manifestNumber, manNum);
  return SUCCESS;
}

/* 
 * Write out the thisUpdate date
 */
int write_thisUpdate(void* man, void* value)
{
  //Same idea here. Cast the generic parameters, grab the manifest part of the
  // CMS object, clear out the old value and then put in the new one. 
  struct ROA* roa = man;

  if (value == NULL)
    return -1;

  struct Manifest *manp = &roa->content.signedData.encapContentInfo.eContent.manifest;
  clear_casn(&manp->thisUpdate);

  if(write_casn(&manp->thisUpdate,(uchar *)value,strlen(value)) < 0)
    return -1; 
  return SUCCESS;
}

/* 
 * Write out the thisUpdate date
 */
int write_nextUpdate(void* man, void* value)
{
  // Same as the thisUpdate function above. 
  struct ROA* roa = man;

  if (value == NULL)
    return -1;

  struct Manifest *manp = &roa->content.signedData.encapContentInfo.eContent.manifest;
  clear_casn(&manp->nextUpdate);

  if(write_casn(&manp->nextUpdate,(uchar *)value,strlen(value)) < 0)
     return -1;
  return SUCCESS;
}

/**
 * write_MAN_casn_fileList
 * params: two generic pointers, this function should know how handle them
 *
 * This function fills in the manifest file list with file names and hashes
 *
 **/
int write_fileList(void* man, void* value)
{
  //cast the parameter into the correct struct
  struct ROA* roa = man;
  char* filesAndHashes;
  char* buf;
  char* token = ",";

  //Get the manifest pointer
  struct Manifest *manp = &roa->content.signedData.encapContentInfo.eContent.manifest;
  struct FileAndHash* fahp;

  if(value == NULL)
    return -1;
  
  //copy the value into a local copy of the buffer
  filesAndHashes = calloc(strlen((char*)value), sizeof(char));
  memcpy(filesAndHashes, (char*)value, strlen( (char*)value));
  buf = NULL;

  //Clear the original fileList from the template
  clear_casn(&manp->fileList.self);

  //tokenize the ',' separated list. 
  buf=strtok(filesAndHashes,token);
  int num = 0;
  while(buf != NULL)
    {
      // this is for safety. while using the strtok function
      // it's best to work on a copy of the tokenized item
      char* testBuf = calloc(strlen(buf), sizeof(char));
      memcpy(testBuf, buf,strlen(buf));
      int fileNameLen;
      char* hash = NULL;
      
      //Set up two char lengths 
      hash = strchr(testBuf,'%');
      fileNameLen = (char*)hash - (char*)testBuf;
      hash++;

      //Build the hash bits
      uchar* hashBits = NULL;
      hashBits = calloc( (strlen(hash)/2)+1, sizeof(char));

      //get a null terminated filename to copy into the casn
      char* fileName = calloc(fileNameLen+1,sizeof(char));
      memcpy(fileName,testBuf,fileNameLen);

      //Use a function in create_utils.c to read the hex value from 
      // the string. 
      if( read_hex_val(hash, strlen(hash), &hashBits[1]) > 0 )
	{
	  if(fileName != NULL && hashBits != NULL)
	    {
	      //Use the ASN library functions to insert a new file in the fileList 
	      // structure
	      if (!(fahp = (struct FileAndHash *)inject_casn(&manp->fileList.self, num))) 
		warn(3, "fileList");
	      write_casn(&fahp->file, (uchar *)fileName, strlen(fileName));
	      write_casn(&fahp->hash, hashBits, (strlen(hash)/2));
	    }      

	  num++;
	}
      buf=strtok(NULL,",");
      free(testBuf);
      free(fileName);
    }
  return SUCCESS;
}

// This is the generic table that describes all input 
// options to a manifest
struct object_field manifest_field_table[] = 
  {
    {"outputfilename", TEXT, NULL, REQUIRED, NULL},        // output filename for the manifest
    {"manNum",INTEGER, 0, OPTIONAL, write_manNum},            // sequence number
    {"thisUpdate", TEXT, NULL,OPTIONAL, write_thisUpdate},
    {"nextUpdate", TEXT, NULL,OPTIONAL, write_nextUpdate},
    {"fileList", TEXT, NULL,OPTIONAL, write_fileList},
    {"EECertLocation",TEXT, NULL,OPTIONAL, write_EEcert},
    {"EEKeyLocation",TEXT, NULL,OPTIONAL, write_EEkey},
    {NULL,TEXT,NULL,OPTIONAL,NULL}
  }; 

/**
 * Accessor for the above manifest table. 
 *
 */
struct object_field *get_man_field_table()
{
  return manifest_field_table;
}

/**
 * create_manifest is the main function call to start the process of
 *  creating a manifest file
 *
 * Params: type -    
 *         table - the filled in object_field that we should fill the new file with
 * Returns:
 **/
int create_manifest(struct object_field *table)
{
  struct ROA roa;
  struct FileListInManifest *f;
  //struct CMSAlgorithmIdentifier *algidp;
   
  ROA(&roa, 0);

  if (!templateFile) {
    templateFile = man_template;
  }

  // Read the manifest template into this manifest
  if (get_casn_file(&roa.self, (char*)templateFile, 0) < 0)
    {
      warn(FILE_OPEN_ERR, (char*)templateFile);
      return(FILE_OPEN_ERR);
    }

  // Remove existing manifest file list.
  f = &roa.content.signedData.encapContentInfo.eContent.manifest.fileList;
  eject_all_casn(&f->self);

  //Setup the outerlying CMS structure
  int i = 0;
  //Populate the manifest information for everything that has a function pointer stored in it
  for(i=0; table[i].name != NULL; i++)
    {
      if(table[i].func != NULL)
	{
	  if (table[i].value != NULL)
	    {
	      //This is useful to allow us to have a loop over all 
	      // of the manifest table fields. This is an extremely 
	      // generic call to a function pointer in the table
	      if(table[i].func(&roa,table[i].value) != SUCCESS)
		{
		  return -1;
		}
	    }
	  }
      }

  //write the new file out
  char* fileName = table[0].value;
  if (put_casn_file(&roa.self, fileName, 0) < SUCCESS)
    {
      printf("fail\n");
      return -1;
    }
  return SUCCESS;
}

