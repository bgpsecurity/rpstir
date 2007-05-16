/*
  $Id$
*/

#include "roa_utils.h"

#define SKI_SIZE 20

// ROA_utils.h contains the headers for including these functions

// NOTE: it is assumed, when calling the address translation functions,
//  that the ROA has
//  been validated at entry and that ipaddrmax exceeds ipaddrmin

// A quick itoa implementation that works only for radix <= 10
static int itoa (int n, char* cN, int radix){
  int i = 0;
  int j = 0;
  char* s;

  if ((radix > 10) ||
      (NULL == cN))
    return ERR_SCM_INVALARG;
  
  s = (char*) calloc(33, sizeof(char));
  if ( s == NULL )
    return ERR_SCM_NOMEM;
  
  do{
    s[i++]=(char)( n % radix + '0');
    n -= n % radix;
  }
  while((n/=radix) > 0);

  for (j = 0; j < i; j++)
    cN[i-1-j] = s[j];

  cN[j]='\0';
  free(s);
  return 0;
}

static int cvalhtoc2(unsigned char cVal, unsigned char *c2Array)
{
  char cHigh = 0;
  char cLow = 0;

  if (NULL == c2Array)
    return ERR_SCM_INVALARG;

  cLow = cVal & 0x0f;
  cHigh = ((cVal & 0xf0) >> 4);

  if (cLow > 0x09)
    cLow += 'A' - 10;
  else
    cLow += '0';

  if (cHigh > 0x09)
    cHigh += 'A' - 10;
  else
    cHigh += '0';

  c2Array[0] = cHigh;
  c2Array[1] = cLow;

  return 0;
}

static int cvaldtoc3(unsigned char cVal, unsigned char *c2Array, int* iLength)
{
  char cHigh = 0;
  char cMid = 0;
  char cLow = 0;

  if (NULL == c2Array)
    return ERR_SCM_INVALARG;

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
  
  return 0;
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
      cReturn = calloc(1 + (SKI_SIZE * 3), sizeof(char));
      if (NULL == cReturn)
	{
//	  free(cSID);
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
      cReturn[(3*(i-1)) + 2] = 0x00;
      return cReturn;
    }

  return NULL;
}

static unsigned char* printIPv4String(unsigned char* array, int iArraySize, int iFill, int iPrintPrefix)
{
  int i = 0;
  unsigned char j = 0;
  int iSecLen = 0;
  int iReturnLen = 0;
  unsigned char cPrefix = 0;
  unsigned char* cReturnString = NULL;
  unsigned char cDecimalSection[3];

  if (NULL == array)
    return NULL;

  // JFG - Cast from int to char == BAD
  cPrefix = 8 * (unsigned char)(iArraySize - 1) - array[0];
  cReturnString = calloc(19, sizeof(char));
  if (NULL == cReturnString)
    return NULL;

  for (i = 1; i < iArraySize; i++)
    {
      // If this is the last char in the array, and we're obeying DER rules
      //  for the maximum in a prefix (i.e. Fill is 1), then we need to add
      //  back the removed '1' bits (aka array[0])
      if ((1 == iFill) && (i == iArraySize - 1))
	{
	  for (j = 0; j < array[0]; j++)
	    array[i] |= (0x01 << j);
	}
      cvaldtoc3(array[i], cDecimalSection, &iSecLen);
      memcpy(cReturnString + iReturnLen, cDecimalSection, iSecLen);
      iReturnLen += iSecLen;
      // Interleaved periods (up to array maximum)
      if (4 > i)
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
	  // Interleaved periods (continued)
	  if (4 > i)
	    {
	      memcpy(cReturnString + iReturnLen, ".", 1);
	      iReturnLen++;
	    }
	}
    }

  // If we're printing prefixes, we need the array to either not be
  //  full length or to have unused bits mentioned in array[0]
  if ((cTRUE == iPrintPrefix) &&
      (32 != cPrefix))
    {
      memcpy(cReturnString + iReturnLen, "/", 1);
      iReturnLen++;
      cvaldtoc3(cPrefix, cDecimalSection, &iSecLen);
      memcpy(cReturnString + iReturnLen, cDecimalSection, iSecLen);
      iReturnLen += iSecLen;
    }

  return cReturnString;
}

static unsigned char* interpretIPv4Prefix(unsigned char* prefixArray, int iPArraySize)
{
  // parameter check
  if (NULL == prefixArray)
    return NULL;

  return printIPv4String(prefixArray, iPArraySize, 0, cTRUE);
}

#ifdef IP_RANGE_ALLOWED
static unsigned char* interpretIPv4Range(unsigned char* minArray, int iMinArraySize, unsigned char* maxArray, int iMaxArraySize)
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

  cMinString = printIPv4String(minArray, iMinArraySize, 0, cFALSE);
  if (NULL == cMinString)
    return NULL;
  cMaxString = printIPv4String(maxArray, iMaxArraySize, 1, cFALSE);
  if (NULL == cMaxString)
    {
      free(cMinString);
      return NULL;
    }

  iMinStringLen = strlen((char*)cMinString);
  iMaxStringLen = strlen((char*)cMaxString);

  cReturnString = calloc((iMinStringLen + iMaxStringLen + 2), sizeof(char));
  if (NULL == cReturnString)
    {
      //      free(cMinString);
      //      free(cMaxString);
      return NULL;
    }

  memcpy(cReturnString, cMinString, iMinStringLen);
  memcpy(cReturnString + iMinStringLen, "-", 1);
  memcpy(cReturnString + iMinStringLen + 1, cMaxString, iMaxStringLen);

  free(cMinString);
  free(cMaxString);

  return cReturnString;
}
#endif

static unsigned char* printIPv6String(unsigned char* array, int iArraySize, int iFill, int iPrintPrefix)
{
  int i = 0;
  unsigned char j = 0;
  int iSecLen = 0;
  int iReturnLen = 0;
  unsigned char cPrefix = 0;
  unsigned char* cReturnString = NULL;
  unsigned char cHexSection[2];
  unsigned char cDecimalPrefix[3];

  if (NULL == array)
    return NULL;

  // JFG - Cast from int to char == BAD
  cPrefix = 8 * (unsigned char)(iArraySize - 1) - array[0];
  cReturnString = calloc(44, sizeof(char));
  if (NULL == cReturnString)
    return NULL;

  for (i = 1; i < iArraySize; i++)
    {
      // If this is the last char in the array, and we're obeying DER rules
      //  for the maximum in a prefix (i.e. Fill is 1), then we need to add
      //  back the removed '1' bits in the prefix (array[0])
      if ((1 == iFill) && (i == iArraySize - 1))
	{
	  for (j = 0; j < array[0]; j++)
	    array[i] |= (0x01 << j);
	}
      cvalhtoc2(array[i], cHexSection);
      memcpy(cReturnString + iReturnLen, cHexSection, 2);
      iReturnLen += 2;
      // Interleaved colons
      if ((16 > i) && (0 == i % 2))
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

  // If we're printing prefixes, we need the array to either not be
  //  full length or to have unused bits mentioned in array[0]
  if ((cTRUE == iPrintPrefix) &&
      (128 != cPrefix))
    {
      memcpy(cReturnString + iReturnLen, "/", 1);
      iReturnLen++;
      cvaldtoc3(cPrefix, cDecimalPrefix, &iSecLen);
      memcpy(cReturnString + iReturnLen, cDecimalPrefix, iSecLen);
      iReturnLen += iSecLen;
    }

  return cReturnString;
}

static unsigned char* interpretIPv6Prefix(unsigned char* prefixArray, int iPArraySize)
{
  // parameter check
  if (NULL == prefixArray)
    return NULL;

  return printIPv6String(prefixArray, iPArraySize, 0, cTRUE);
}

#ifdef IP_RANGE_ALLOWED
static unsigned char* interpretIPv6Range(unsigned char* minArray, int iMinArraySize, unsigned char* maxArray, int iMaxArraySize)
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

  cMinString = printIPv6String(minArray, iMinArraySize, 0, cFALSE);
  if (NULL == cMinString)
    return NULL;
  cMaxString = printIPv6String(maxArray, iMaxArraySize, 1, cFALSE);
  if (NULL == cMaxString)
    {
      free(cMinString);
      return NULL;
    }

  iMinStringLen = strlen((char*)cMinString);
  iMaxStringLen = strlen((char*)cMaxString);

  cReturnString = calloc((iMinStringLen + iMaxStringLen + 2), sizeof(char));
  if (NULL == cReturnString)
    {
      //      free(cMinString);
      //      free(cMaxString);
      return NULL;
    }

  memcpy(cReturnString, cMinString, iMinStringLen);
  memcpy(cReturnString + iMinStringLen, "-", 1);
  memcpy(cReturnString + iMinStringLen + 1, cMaxString, iMaxStringLen);

  free(cMinString);
  free(cMaxString);

  return cReturnString;
}
#endif

#ifdef IP_RANGE_ALLOWED
unsigned char* roaIPAddrOrRange(struct IPAddressOrRangeA *addrOrRange, int iFamily)
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
      // Check to see if we have a prefix or a range
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
#endif // IP_RANGE_ALLOWED

static unsigned char* roaIPAddr(struct IPAddress *addr, int iFamily)
{
  int iSize = 0;
  unsigned char *cASCIIString = NULL;
  unsigned char ipv4array[5];
  unsigned char ipv6array[17];

  // parameter check
  if ((NULL == addr) ||
      (0 == iFamily))
    return NULL;
  
  if (IPV4 == iFamily)
    {
      memset(ipv4array, 0, 5);

      iSize = vsize_casn(addr);
      if ((0 >= iSize) || (5 < iSize))
	return NULL;
      if (0 > read_casn(addr, ipv4array))
	return NULL;
      cASCIIString = interpretIPv4Prefix(ipv4array, iSize);
    }
  else if (IPV6 == iFamily)
    {
      memset(ipv6array, 0, 17);

      iSize = vsize_casn(addr);
      if ((0 >= iSize) || (17 < iSize))
	return NULL;
      if (0 > read_casn(addr, ipv6array))
	return NULL;
      cASCIIString = interpretIPv6Prefix(ipv6array, iSize);
    }
  else
    return NULL;

  return cASCIIString;
}

static unsigned char **roaIPAddresses(struct ROAIPAddressFamily *roapAddrFam, int *numOfAddresses)
{
  int i,j = 0;
  int iRes = 0;
  int iFamily = 0;
  int iAddrs = 0;
  unsigned char** pcAddresses = NULL;
  unsigned char family[3];

#ifdef IP_RANGES_ALLOWED
  struct IPAddressOrRangeA *roaAddr = NULL;
#else
  struct IPAddress *roaAddr = NULL;
#endif

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

#ifdef IP_RANGES_ALLOWED
  iAddrs = num_items(&(roapAddrFam->addressesOrRanges.self));
#else
  iAddrs = num_items(&(roapAddrFam->addresses.self));
#endif // IP_RANGES_ALLOWED

  if (0 >= iAddrs)
    return NULL;

  pcAddresses = (unsigned char**) calloc(iAddrs, sizeof(char **));
  if (NULL == pcAddresses)
    return NULL;

  for (i = 0; i < iAddrs; i++)
    {
#ifdef IP_RANGES_ALLOWED
      roaAddr = (struct IPAddressOrRangeA*) member_casn(&(roapAddrFam->addressesOrRanges.self), i);
      pcAddresses[i] = roaIPAddrOrRange(roaAddr, iFamily);
#else
      roaAddr = (struct IPAddress*) member_casn(&(roapAddrFam->addresses.self), i);
      pcAddresses[i] = roaIPAddr(roaAddr, iFamily);
#endif // IP_RANGES_ALLOWED
      if (NULL == pcAddresses[i])
	{
	  for (j = i - 1; j >= 0; j--)
	    free(pcAddresses[j]);
	  free(pcAddresses);
	  return NULL;
	}
    }

  *numOfAddresses = iAddrs;
  return pcAddresses;
}

int roaAS_ID(struct ROA *r)
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
  int i,j = 0;
  int iRes = 0;
  int iFamilies = 0;
  int iAddrNum = 0;
  int iAS_ID = 0;
  int sta;
  char cAS_ID[17];
  unsigned char *cSID = NULL;
  unsigned char **pcAddresses = NULL;
  struct ROAIPAddressFamily *roaFamily = NULL;

  UNREFERENCED_PARAMETER(cert);
  // parameter check
  if (NULL == fp)
    return ERR_SCM_INVALARG;

  memset(cAS_ID, 0, 17);
  iAS_ID = roaAS_ID(r);
  if ( iAS_ID == 0 )
    return ERR_SCM_INVALASID;
  sta = itoa(iAS_ID, cAS_ID, 10);
  if ( sta < 0 )
    return sta;

  cSID = roaSKI(r);
  if (NULL == cSID)
    return ERR_SCM_INVALSKI;

  // For each family, print out all triplets beginning with SKI and AS#
  // and ending with each IP address listed in the ROA
  iFamilies = num_items(&(r->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self));
  for (i = 0; i < iFamilies; i++)
    {
      roaFamily = (struct ROAIPAddressFamily*) member_casn(&(r->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), i);
      if (NULL == roaFamily)
	{
	  free(cSID);
	  return ERR_SCM_INVALIPB;
	}
      pcAddresses = roaIPAddresses(roaFamily, &iAddrNum);
      if (NULL == pcAddresses)
	{
	  free(cSID);
	  return ERR_SCM_INVALIPB;
	}

      for (j = 0; j < iAddrNum; j++)
	{
	  iRes = fprintf(fp, "%s  %s  %s\n", cSID, cAS_ID, pcAddresses[j]);
	  if (0 > iRes)
	    return ERR_SCM_BADFILE;
	}
      for (j = iAddrNum - 1; j >= 0; j--)
	free(pcAddresses[j]);
      free(pcAddresses);
      pcAddresses = NULL;
    }

  return 0;
}
