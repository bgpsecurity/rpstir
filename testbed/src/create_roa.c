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
 * Copyright (C) Raytheon BBN Technologies Corp. 2008-2010.  All Rights Reserved.
 *
 * Contributor(s):  Brenton N. Kohler
 *
 * ***** END LICENSE BLOCK ***** */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
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

char *roa_template = "../templates/R.roa";
void print_table(struct object_field *table);
int write_EEcert(void* my_var, void* value);
int write_EEkey(void* my_var, void* value);
int encode_ipAddr(int family,char *ipAddr, uchar *enc_addr);
/**
 *
 * This file is designed to provide functions to create a roa
 *  from a template. 
 *
 **/

/**
 * Writes the AS number of the issue into this ROA
 **/
int write_asID(void* my_var, void* value)
{
  // first cast the generic parameters and then write in the value to the 
  // correct location in the ROA CMS structure
  struct ROA* roa = my_var;
  if( value == NULL)
    return -1;

  long asNum = strtol(((char*)value), NULL, 0);

  //clear_casn(&roa->content.signedData.encapContentInfo.eContent.roa.asID);
  if(write_casn_num(&roa->content.signedData.encapContentInfo.eContent.roa.asID,asNum) <=0)
    return -1;

  return SUCCESS;
}

/**
 * This parses the ptr and puts all the IP addresses into the roap. 
 * addrFam should be 1 for ipv4 and 2 for ipv6
 * numFam should be the count of current address families in your structure
 *
 **/
int parse_and_write_ips(struct RouteOriginAttestation* roap, char* ptr, long addrFam, int numFam)
{
  char *next, *ipAddr, *buf;
  char* token=",";
  int numIps = 0;
  char family[2];
  int var;

  family[0]= 0;
  // if we are dealing with IPv4, set up some variables
  if (addrFam==1)
    {
      family[1]= 1;
      var = AF_INET;
    }
  else
    {
      family[1]= 2;
      var = AF_INET6;
    }

  // Grab the correct structure from the ROA CMS object
  struct ROAIPAddressFamily *roaipfp = (struct ROAIPAddressFamily *)
    inject_casn(&roap->ipAddrBlocks.self, numFam);

  //Write in the identifier for the IP version 
  if(write_casn(&roaipfp->addressFamily, (uchar*)family,2)<0)
    return -1;

  //Safe use of the strtok function is to make a local copy of the
  // string you are tokenizing
  buf = calloc(strlen(ptr)+1,sizeof(char));
  memcpy(buf, ptr, strlen(ptr));

  next = strtok(buf,token);
  while(next != NULL)
    {
      int ipAddrLen;
      char* maxLen = NULL;

      //Inject another IP address into the ROA CMS object
      struct ROAIPAddress *roafp = (struct ROAIPAddress *)
	inject_casn(&roaipfp->addresses.self, numIps);

      numIps++;

      //Handle the writing of the maxLength
      maxLen = strrchr(next,'%');
      if(maxLen != NULL)
	{
	  ipAddrLen = (char*)maxLen - (char*)next;  
	  maxLen++;
	  
	  long max = strtol(((char*)maxLen), NULL, 0);

	  //get a null terminated ipAddr to copy into the casn
	  ipAddr = calloc(ipAddrLen+1,sizeof(char));
	  memcpy(ipAddr,next,ipAddrLen);
	  ipAddr[ipAddrLen+1]='\0';
	  if(write_casn_num(&roafp->maxLength, max)<0)
	    return -1;
	}
      else
	{
	  ipAddr = next;
	  //if(write_casn_num(&roafp->maxLength, 0)<0)
	  //  return -1;
	}

      //A buffer to send to the inet_pton function which takes care of parsing
      // the IP address
      uchar ipBits[18];
      int len;
      
      memset(ipBits, 0, 18);
      if((len = encode_ipAddr(var,ipAddr,ipBits)) > 0)
	{
	  if(write_casn(&roafp->address, (uchar*)ipBits,len) != len)
	    return -1;
	}
      else
	{
	  printf("The IP Address you passed in is not IPv4 or IPv6\n");
	  return -1;
	}
      next = strtok(NULL,token);
    }
  return SUCCESS;
}

// encode the ascii ip address into an encoded bit string
// will handle prefixes but not ranges(not supported for roas)
// i.e. 1.0/14 encodes to 020100
int encode_ipAddr(int family, char *ipAddr, uchar *enc_addr)
{
  
  int lth = (family==AF_INET) ? 4:16;
  uchar lolim[18], hilim[18];
  uchar *hucp, *lucp, *eucp = &lolim[lth];
  uchar mask = 0;
  int numbits = 0;
  
  memset(lolim, 0, 16);
  memset(hilim, 0xFF, 16);

  if (family == AF_INET)
    {
      cvtv4(0,ipAddr, lolim);
      cvtv4(0xFF,ipAddr, hilim);
    }  
  else
    {
      cvtv6(0,ipAddr, lolim);
      cvtv6(0xFF,ipAddr, hilim);
    }  

  for (lucp = lolim, hucp = hilim;
       lucp < eucp && *lucp == *hucp;
       lucp++,  hucp++, numbits += 8);
  if (lucp < eucp)
    {
      for (mask = 0x80; mask && (mask & *lucp) == (mask & *hucp);
	   mask >>= 1, numbits++);
    }
  // at first difference. test remains of byte
  while(mask && !(mask & *lucp) && (mask & *hucp)) mask >>= 1;

  if (!mask) // now test remainder of bytes
    {
      for (lucp++, hucp++; lucp < eucp && !*lucp && *hucp == 0xff;
	   lucp++, hucp++);
    }

  if (!mask && lucp >= eucp)                
    {
      int strlth = 0;
      strlth = (numbits + 7) >> 3;
      memcpy(&enc_addr[1], lolim, strlth);
      enc_addr[0] = (8 - (numbits & 7)) & 7;
      return strlth + 1;
    }

  return 0;
}


/**
 * Writes a set of IP v4 addresses into the list of addreses for
 * the address family
 *
 **/
int write_ipv4(void* my_var, void* value)
{
  // Casts generic parameters and then calls the function above
  if(my_var == NULL)
    return -1;
  struct ROA* roa = my_var;
  struct RouteOriginAttestation* roap = (struct RouteOriginAttestation*)
    &roa->content.signedData.encapContentInfo.eContent.roa.self;
  
  if(value == NULL)
    return -1;

  char *ptr = (char*) value;

  clear_casn(&roap->ipAddrBlocks.self);

  if(parse_and_write_ips(roap,ptr,(long)1,0) == SUCCESS)
    return SUCCESS;
  else
    return -1;
}

/**
 * Writes a set of IP v6 addresses into the list of addreses for
 * the address family
 *
 **/
int write_ipv6(void* my_var, void* value)
{
  // Casts generic parameters and then calls the function above
  if(my_var == NULL)
    return -1;
  struct ROA* roa = my_var;
  struct RouteOriginAttestation* roap = (struct RouteOriginAttestation*)
    &roa->content.signedData.encapContentInfo.eContent.roa.self;

  if(value == NULL)
    return -1;

  char *ptr = (char*)value;
  
  if(parse_and_write_ips(roap,ptr,(long)2,1) == SUCCESS)
    return SUCCESS;
  else
    return -1;
}


// This table stores all possible input values for the ROA and a pointer
// to functions that deal with them
struct object_field roa_field_table[] = 
  {
    {"outputfilename",TEXT,NULL,REQUIRED,NULL},
    {"asID",INTEGER,NULL,OPTIONAL,write_asID},
    {"roaipv4",TEXT,NULL,OPTIONAL,write_ipv4},
    {"roaipv6",TEXT,NULL,OPTIONAL,write_ipv6},
    {"EECertLocation",TEXT, NULL,OPTIONAL,write_EEcert},
    {"EEKeyLocation",TEXT, NULL,OPTIONAL,write_EEkey},
    {NULL,0,NULL,0,NULL}
  }; 

/**
 * Accesor function for the above table
 *
 **/
struct object_field *get_roa_field_table()
{
  return roa_field_table;
}

/**
 * create_roa is the main function call to start the process of
 *  creating a roa file
 *
 * Params: roa - the filled in object_field that we should fill the new file with
 * Returns: 
 **/
int create_roa(struct object_field *table)
{
    struct ROA roa;

    // init roa
    ROA(&roa, (ushort)0);

    // Read the manifest template into this manifest
    if (get_casn_file(&roa.self,  roa_template, 0) < 0)
      {
	warn(FILE_OPEN_ERR, roa_template);
	return(FILE_OPEN_ERR);
      }
    
    int i = 0;
    //Populate the ROA information for everything that has a function pointer stored in it
    for(i=0; table[i].name != NULL; i++)
    {
      if(table[i].func != NULL)
	{
	  if (table[i].value != NULL)
	    {
	      //This is the generic function call from the table
	      if(table[i].func(&roa,table[i].value) != SUCCESS)
		return -1;
	    }
	}
    }


    if (put_casn_file(&roa.self, table[0].value, 0) < 0)
      {
	printf("fail\n");
	return -1;
      }
    return 0;
}
