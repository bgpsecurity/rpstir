/*
  $Id$
*/

#include "roa_utils.h"

#define SKI_SIZE 20

// ROA_utils.h contains the headers for including these functions

// NOTE: it is assumed, when calling the address translation functions,
//  that the ROA has
//  been validated at entry and that ipaddrmax exceeds ipaddrmin

int cvalhtoc2(unsigned char cVal, unsigned char *c2Array)
{
  char cHigh = 0;
  char cLow = 0;

  if (NULL == c2Array)
    return FALSE;

  cLow = cVal & 0x0f;
  cHigh = ((cVal & 0xf0) >> 4);

  if (cLow > 0x09)
    cLow += 'A';
  else
    cLow += '0';

  if (cHigh > 0x09)
    cHigh += 'A';
  else
    cHigh += '0';

  c2Array[0] = cHigh;
  c2Array[1] = cLow;

  return TRUE;  
}

int cvaldtoc3(unsigned char cVal, unsigned char *c2Array, int* iLength)
{
  char cHigh = 0;
  char cMid = 0;
  char cLow = 0;

  if (NULL == c2Array)
    return FALSE;

  cLow = cVal % 10;
  cHigh = cVal / 10;

  cMid = cHigh % 10;
  cHigh = cHigh / 10;

  cLow += '0';
  cMid += '0';
  cHigh += '0';

  if ('0' != cHigh)
    {
      c2Array[0] = cHigh;
      c2Array[1] = cMid;
      c2Array[2] = cLow;
      *iLength = 3;
    }
  else if ('0' != cMid)
    {
      c2Array[0] = cMid;
      c2Array[1] = cLow;
      *iLength = 2;
    }
  else
    {
      c2Array[0] = cLow;
      *iLength = 1;
    }
  
  return TRUE;  
}

unsigned char *roaSKI(struct ROA *r)
{
  int i = 0;
  unsigned char *cSID = NULL;
  unsigned char *cReturn = NULL;
  unsigned char c2Ans[2];

  // parameter check
  if (NULL == r)
    return NULL;

  if (SKI_SIZE != vsize_casn(&(r->content.content.signerInfos.signerInfo.sid.subjectKeyIdentifier)))
    return NULL;
  if (0 > readvsize_casn(&(r->content.content.signerInfos.signerInfo.sid.subjectKeyIdentifier), &cSID))
    return NULL;
  else
    {
      cReturn = malloc(SKI_SIZE * 3);
      if (NULL == cReturn)
	{
	  free(cSID);
	  return NULL;
	}
      for (i = 0; i < SKI_SIZE; i++)
	{
	  cvalhtoc2(cSID[i], c2Ans);
	  cReturn[(3*i)] = c2Ans[0];
	  cReturn[(3*i) + 1] = c2Ans[1];
	  cReturn[(3*i) + 2] = ':';
	}
      // Clear the incorrectly allocated : in the last loop
      cReturn[(3*i) + 2] = 0x00;
      return cReturn;
    }

  return NULL;
}

unsigned char* printIPv4String(unsigned char* array, int iArraySize, int iFill, int iPrintPrefix)
{
  int i = 0;
  int iSecLen = 0;
  int iReturnLen = 0;
  unsigned char cPrefix = 0;
  unsigned char* cReturnString = NULL;
  unsigned char cDecimalSection[3];

  if (NULL == array)
    return NULL;

  cPrefix = array[0];  
  cReturnString = malloc(19);
  if (NULL == cReturnString)
    return NULL;

  memset(cReturnString, 0, 19);
  for (i = 1; i < iArraySize; i++)
    {
      cvaldtoc3(array[i], cDecimalSection, &iSecLen);
      memcpy(cReturnString + iReturnLen, cDecimalSection, iSecLen);
      iReturnLen += iSecLen;
      if (iArraySize - 1 != i)
	{
	  memcpy(cReturnString + iReturnLen, ".", 1);
	  iReturnLen++;
	}
    }

  if (iArraySize < 5)
    {
      for (; i < 5; i++)
	{
	  if (1 == iFill) 
	    {
	      memcpy(cReturnString + iReturnLen, "255", 3);
	      iReturnLen += 3;
	    }
	  else if (0 == iFill)
	    {
	      memcpy(cReturnString + iReturnLen, "0", 1);
	      iReturnLen++;
	    }
	  // Interleaved periods
	  if (4 > i)
	    {
	      memcpy(cReturnString + iReturnLen, ".", 1);
	      iReturnLen++;
	    }
	}
    }

  if (TRUE == iPrintPrefix)
    {
      memcpy(cReturnString + iReturnLen, "/", 1);
      iReturnLen++;
      cvaldtoc3(array[0], cDecimalSection, &iSecLen);
      memcpy(cReturnString + iReturnLen, cDecimalSection, iSecLen);
      iReturnLen += iSecLen;
    }

  return cReturnString;
}

unsigned char* interpretIPv4Prefix(unsigned char* prefixArray, int iPArraySize)
{
  // parameter check
  if (NULL == prefixArray)
    return NULL;

  return printIPv4String(prefixArray, iPArraySize, 0, TRUE);
}

unsigned char* interpretIPv4Range(unsigned char* minArray, int iMinArraySize, unsigned char* maxArray, int iMaxArraySize)
{
  int iMinStringLen = 0;
  int iMaxStringLen = 0;
  unsigned char* cMinString = NULL;
  unsigned char* cMaxString = NULL;
  unsigned char* cReturnString = NULL;

  // parameter check
  if ((NULL == minArray) ||
      (NULL == maxArray))
    return NULL;

  cMinString = printIPv4String(minArray, iMinArraySize, 0, FALSE);
  if (NULL == cMinString)
    return NULL;
  cMaxString = printIPv4String(maxArray, iMaxArraySize, 1, FALSE);
  if (NULL == cMaxString)
    {
      free(cMinString);
      return NULL;
    }

  iMinStringLen = strlen((char*)cMinString);
  iMaxStringLen = strlen((char*)cMaxString);

  cReturnString = malloc((iMinStringLen + iMaxStringLen + 2) * sizeof(char));
  if (NULL == cReturnString)
    {
      free(cMinString);
      free(cMaxString);
      return NULL;
    }

  memcpy(cReturnString, cMinString, iMinStringLen);
  memcpy(cReturnString + iMinStringLen, "-", 1);
  memcpy(cReturnString + iMinStringLen + 1, cMaxString, iMaxStringLen);

  free(cMinString);
  free(cMaxString);

  return cReturnString;
}


unsigned char* printIPv6String(unsigned char* array, int iArraySize, int iFill, int iPrintPrefix)
{
  int i = 0;
  int iSecLen = 0;
  int iReturnLen = 0;
  unsigned char cPrefix = 0;
  unsigned char* cReturnString = NULL;
  unsigned char cHexSection[2];
  unsigned char cDecimalPrefix[3];

  if (NULL == array)
    return NULL;

  cPrefix = array[0];  
  cReturnString = malloc(44);
  if (NULL == cReturnString)
    return NULL;

  memset(cReturnString, 0, 44);
  for (i = 1; i < iArraySize; i++)
    {
      cvalhtoc2(array[i], cHexSection);
      memcpy(cReturnString + iReturnLen, cHexSection, 2);
      iReturnLen += 2;
      if ((iArraySize - 1 >= i) && (0 == i % 2))
	{
	  memcpy(cReturnString + iReturnLen, ":", 1);
	  iReturnLen++;
	}
    }
  if (iArraySize < 17)
    {
      for (; i < 17; i++)
	{
	  if (1 == iFill) 
	    {
	      memcpy(cReturnString + iReturnLen, "FF", 2);
	      iReturnLen += 2;
	    }
	  else if (0 == iFill)
	    {
	      memcpy(cReturnString + iReturnLen, "00", 2);
	      iReturnLen += 2;
	    }
	  // Every other translated byte needs a colon
	  if ((16 > i) && (0 == i % 2))
	    {
	      memcpy(cReturnString + iReturnLen, ":", 1);
	      iReturnLen++;
	    }
	}
    }

  if (TRUE == iPrintPrefix)
    {
      memcpy(cReturnString + iReturnLen, "/", 1);
      iReturnLen++;
      cvaldtoc3(array[0], cDecimalPrefix, &iSecLen);
      memcpy(cReturnString + iReturnLen, cDecimalPrefix, iSecLen);
      iReturnLen += iSecLen;
    }

  return cReturnString;
}

unsigned char* interpretIPv6Prefix(unsigned char* prefixArray, int iPArraySize)
{
  // parameter check
  if (NULL == prefixArray)
    return NULL;

  return printIPv6String(prefixArray, iPArraySize, 0, TRUE);
}

unsigned char* interpretIPv6Range(unsigned char* minArray, int iMinArraySize, unsigned char* maxArray, int iMaxArraySize)
{
  int iMinStringLen = 0;
  int iMaxStringLen = 0;
  unsigned char* cMinString = NULL;
  unsigned char* cMaxString = NULL;
  unsigned char* cReturnString = NULL;

  // parameter check
  if ((NULL == minArray) ||
      (NULL == maxArray))
    return NULL;

  cMinString = printIPv6String(minArray, iMinArraySize, 0, FALSE);
  if (NULL == cMinString)
    return NULL;
  cMaxString = printIPv6String(maxArray, iMaxArraySize, 1, FALSE);
  if (NULL == cMaxString)
    {
      free(cMinString);
      return NULL;
    }

  iMinStringLen = strlen((char*)cMinString);
  iMaxStringLen = strlen((char*)cMaxString);

  cReturnString = malloc((iMinStringLen + iMaxStringLen + 2) * sizeof(char));
  if (NULL == cReturnString)
    {
      free(cMinString);
      free(cMaxString);
      return NULL;
    }

  memcpy(cReturnString, cMinString, iMinStringLen);
  memcpy(cReturnString + iMinStringLen, "-", 1);
  memcpy(cReturnString + iMinStringLen + 1, cMaxString, iMaxStringLen);

  free(cMinString);
  free(cMaxString);

  return cReturnString;
}

unsigned char* roaIPAddr(struct IPAddressOrRangeA *addrOrRange, int iFamily)
{
  int iSize = 0;
  int iSize2 = 0;
  int iTag = 0;
  unsigned char *cASCIIString = NULL;
  unsigned char ipv4array[5];
  unsigned char ipv6array[17];
  unsigned char ipv4array2[5];
  unsigned char ipv6array2[17];

  // parameter check
  if ((NULL == addrOrRange) ||
      (0 == iFamily))
    return NULL;
  
  if (IPV4 == iFamily)
    {
      memset(ipv4array, 0, 5);
      memset(ipv4array2, 0, 5);
      // Check to see if we have a prefix or an address
      iTag = tag_casn(&(addrOrRange->self));
      if (ASN_BITSTRING == (0x1F & iTag))
	{
	  iSize = vsize_casn(&(addrOrRange->addressPrefix));
	  if ((0 >= iSize) || (5 < iSize))
	    return NULL;
	  if (0 > read_casn(&(addrOrRange->addressPrefix), ipv4array))
	    return NULL;
	  cASCIIString = interpretIPv4Prefix(ipv4array, iSize);
	}
      else
	{
	  iSize = vsize_casn(&(addrOrRange->addressRange.min));
	  if ((0 >= iSize) || (5 < iSize))
	    return NULL;
	  if (0 > read_casn(&(addrOrRange->addressRange.min), ipv4array))
	    return NULL;
	  iSize2 = vsize_casn(&(addrOrRange->addressRange.max));
	  if ((0 >= iSize2) || (5 < iSize2))
	    return NULL;
	  if (0 > read_casn(&(addrOrRange->addressRange.max), ipv4array2))
	    return NULL;
	  cASCIIString = interpretIPv4Range(ipv4array, iSize, ipv4array2, iSize2);
	}
    }
  else if (IPV6 == iFamily)
    {
      memset(ipv6array, 0, 17);
      memset(ipv6array2, 0, 17);
      // Check to see if we have a prefix or an address
      iTag = tag_casn(&(addrOrRange->self));
      if (ASN_BITSTRING == (0x1F & iTag))
	{
	  iSize = vsize_casn(&(addrOrRange->addressPrefix));
	  if ((0 >= iSize) || (17 < iSize))
	    return NULL;
	  if (0 > read_casn(&(addrOrRange->addressPrefix), ipv6array))
	    return NULL;
	  cASCIIString = interpretIPv6Prefix(ipv6array, iSize);
	}
      else
	{
	  iSize = vsize_casn(&(addrOrRange->addressRange.min));
	  if ((0 >= iSize) || (17 < iSize))
	    return NULL;
	  if (0 > read_casn(&(addrOrRange->addressRange.min), ipv6array))
	    return NULL;
	  iSize2 = vsize_casn(&(addrOrRange->addressRange.max));
	  if ((0 >= iSize2) || (17 < iSize2))
	    return NULL;
	  if (0 > read_casn(&(addrOrRange->addressRange.max), ipv6array2))
	    return NULL;
	  cASCIIString = interpretIPv6Range(ipv6array, iSize, ipv6array2, iSize2);
	}
    }
  else
    return NULL;

  return cASCIIString;
}

unsigned char **roaIPAddresses(struct ROAIPAddressFamily *roapAddrFam, int *numOfAddresses)
{
  int i,j = 0;
  int iRes = 0;
  int iFamily = 0;
  int iAddrs = 0;
  unsigned char** pcAddresses = NULL;
  unsigned char family[3];
  struct IPAddressOrRangeA *roaAddr = NULL;

  // parameter check
  if ((NULL == roapAddrFam) ||
      (NULL == numOfAddresses))
    return NULL;

  iRes = read_casn(&(roapAddrFam->addressFamily), family);
  if (0 > iRes)
    return NULL;

  if (0x01 == family[1])
    iFamily = IPV4;
  else if (0x02 == family[1])
    iFamily = IPV6;
  else
    return NULL;

  iAddrs = num_items(&(roapAddrFam->addressesOrRanges.self));
  if (0 >= iAddrs)
    return NULL;

  pcAddresses = (unsigned char**) malloc(sizeof(char**) * iAddrs);
  if (NULL == pcAddresses)
    return NULL;

  for (i = 0; i < iAddrs; i++)
    {
      roaAddr = (struct IPAddressOrRangeA*) member_casn(&(roapAddrFam->addressesOrRanges.self), i);
      pcAddresses[i] = roaIPAddr(roaAddr, iFamily);
      if (NULL == pcAddresses[i])
	{
	  for (j = i - 1; j > 0; j--)
	    free(pcAddresses[j]);
	  free(pcAddresses);
	  return NULL;
	}
    }

  *numOfAddresses = iAddrs;
  return pcAddresses;
}

int roaASID(struct ROA *r)
{
  long iAS_ID = 0;

  // parameter check
  if (NULL == r)
    return 0;

  if (0 > read_casn_num(&(r->content.content.encapContentInfo.eContent.roa.asID), &iAS_ID))
    return 0;

  return iAS_ID;
}

void roaFree(struct ROA *r)
{
  if (NULL != r)
    delete_casn(&(r->self));
  return;
}

int roaGenerateFilter(struct ROA *r, X509 *cert, FILE *fp)
{
  // parameter check
  if ((FALSE == roaValidate(r)) ||
      (FALSE == roaValidate2(r, cert)) ||
      (NULL == fp))
    return FALSE;

  // test that all three of the arguments are non-null
  // print roa->content->signerInfoStruct->sid (SKI)
  // print roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->asID
  // print roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressPrefix
  //  - OR -
  // convert roa->content->encapContentInfo->eContent
  //   (RouteOriginAttestation)->ipAddrBlocks->addressRange->{min,max}
  //   to syntactically correct IP format and print it
  //   (call convertAddrsToRange, above)
  // take printed string and write to file

  return FALSE;
}
