/*
  $Id$
*/

// JFG - SYSTEMWIDE TODO: Rationalize return values

#include "roa_utils.h"

// Warning - MAX_LINE hardcoded as a constant in confInterpret;
//  if this changes, that must as well
#define MAX_LINE 512

enum configKeys {
  VERSION = 0,
  SID,
  SIGNATURE,
  AS_ID,
  IPFAM,
  IPADDR,
  IPADDRMIN,
  IPADDRMAX,
  CERTNAME,
  CONFIG_KEY_MAX
};

const char *configKeyStrings[] = {
  "version",
  "SID",
  "signature",
  "as_id",
  "ipfam",
  "ipaddr",
  "ipaddrmin",
  "ipaddrmax",
  "certname"
};

enum forcingInstruction {
  NONE = 0,
  IPV4FAM,
  IPV6FAM,
  IPV4MIN,
  IPV6MIN,
  IPV4CONT,
  IPV6CONT
} g_lastInstruction;

static int g_iIPv4Flag;
static int g_iIPv6Flag;

/*
** Translation Tables as described in RFC1113 (Translation table method
**  courtesy b64.c from Bob Trower @ base64.sourceforge.net)
*/
// Encode table
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// Decode table
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";


// Idiotic START/END ROA armor
static const char roaStart[]="------ BEGIN ROA ------\r\n";
static const char roaEnd[]="------ END ROA ------\r\n";

/////////////////////////////////////////////////////////////
//
// Testing of locally defined enumerations
//
/////////////////////////////////////////////////////////////

inline int isInstructionForcing(enum forcingInstruction fi)
{
  if ((NONE == fi) ||
      (IPV4CONT == fi) ||
      (IPV6CONT == fi))
    return FALSE;
  else
    return TRUE;
}

/////////////////////////////////////////////////////////////
//
// Encode/decode to Base64 functions
//
/////////////////////////////////////////////////////////////

/*
** encodeblock
**
** encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
void encodeblock( unsigned char in[3], unsigned char out[4], int len )
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

/*
** encode
**
** base64 encode a stream adding padding and line breaks as per spec.
** ALLOCATES MEMORY that must be freed elsewhere
*/
int encode_b64( unsigned char *bufIn, int inSize, unsigned char **bufOut, int *outSize, int lineSize )
{
    unsigned char inTemp[3], outTemp[4];
    int i = 0;
    int len = 0;
    int blocksout = 0;
    int inIndex = 0;
    int outIndex = 0;
    int iTempSize = 0;
    int iArmor = 0;
    unsigned char *bufTemp = NULL;

    // Parameter sanity check
    if ((NULL == bufIn) ||
	(0 >= inSize) ||
	(NULL == outSize) ||
	(0 >= lineSize))
      return FALSE;

    iTempSize = 1024;
    bufTemp = (unsigned char *)calloc(1, iTempSize);
    if (NULL == bufTemp)
      return FALSE;

    // Push armoring onto top of file
    iArmor = strlen(roaStart);
    memcpy(bufTemp, roaStart, iArmor);
    outIndex += iArmor;

    // Encode file
    while( inIndex < inSize ) {
        len = 0;
        for( i = 0; i < 3; i++ ) {
            inTemp[i] = (unsigned char) bufIn[inIndex];
            if( inIndex < inSize ) {
                len++;
            }
            else {
                inTemp[i] = 0;
            }
	    inIndex++;
        }
        if( len ) {
            encodeblock( inTemp, outTemp, len );
            for( i = 0; i < 4; i++ ) {
	      if (outIndex >= iTempSize)
		{
		  bufTemp = (unsigned char *)realloc(bufTemp, iTempSize + 1024);
		  iTempSize += 1024;
		}
	      bufTemp[outIndex] = outTemp[i];
	      outIndex++;
            }
            blocksout++;
        }
        if( blocksout >= (lineSize/4) || inIndex >= inSize ) {
            if( blocksout )
	      {
		// We have to add 2 chars, so check one below our limit
		if (outIndex - 1 >= iTempSize)
		  {
		    bufTemp = (unsigned char *)realloc(bufTemp, iTempSize + 1024);
		    iTempSize += 1024;
		  }
		bufTemp[outIndex] = '\r';
		outIndex++;
		bufTemp[outIndex] = '\n';
		outIndex++;
	      }
            blocksout = 0;
        }
    }

    // Push armoring onto bottom of file
    iArmor = strlen(roaEnd);
    if (outIndex + iArmor + 1 >= iTempSize)
      {
	bufTemp = (unsigned char *)realloc(bufTemp, iTempSize + 1024);
	iTempSize += 1024;
      }
    memcpy(&bufTemp[outIndex], roaEnd, iArmor);
    outIndex += iArmor;
    bufTemp[outIndex] = 0x00;

    // Set return values
    *bufOut = bufTemp;
    *outSize = outIndex;
    if (NULL == bufTemp)
      return FALSE;
    else
      return TRUE;
}

/*
** decodeblock
**
** decode 4 '6-bit' characters into 3 8-bit binary bytes
*/
void decodeblock( unsigned char in[4], unsigned char out[3] )
{   
    out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
    out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
    out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}

/*
** decode
**
** decode a base64 encoded stream discarding padding, line breaks and noise
** ALLOCATES MEMORY that must be freed elsewhere
*/
int decode_b64( unsigned char *bufIn, int inSize, unsigned char **bufOut, int *outSize )
{
    unsigned char inTemp[4], outTemp[3], v;
    int i = 0;
    int len = 0;
    int inIndex = 0;
    int outIndex = 0;
    int iTempSize = 0;
    int iArmor = 0;
    unsigned char *bufTemp = NULL;

    // Parameter sanity check
    if ((NULL == bufIn) ||
	(0 >= inSize) ||
	(NULL == outSize))
      return FALSE;

    iTempSize = 1024;
    bufTemp = (unsigned char *)calloc(1, iTempSize);
    if (NULL == bufTemp)
      return FALSE;

    // First, search for armoring at front of file
    while ( 1 )
      {
	if ('-' == bufIn[inIndex])
	  {
	    iArmor = strlen(roaStart);
	    if (0 == strncmp((char*)&bufIn[inIndex], roaStart, iArmor))
	      {
		inIndex += iArmor;
		break;
	      }
	  }
	inIndex++;
      }

    // Decode the translation
    while( inIndex < inSize ) {
         for( len = 0, i = 0; (i < 4) && (inIndex < inSize); i++ ) {
            v = 0;
            while((inIndex < inSize) && (v == 0)) {
                v = (unsigned char) bufIn[inIndex];
		// Skip the end armoring (don't translate its chars)
		if ('-' == v)
		  {
		    iArmor = strlen(roaEnd);
		    if (0 == strncmp((char*)&bufIn[inIndex], roaEnd, iArmor))
		      inIndex += iArmor;
		  }
                v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
                if( v ) {
                    v = (unsigned char) ((v == '$') ? 0 : v - 61);
                }
		inIndex++;
            }
            if( inIndex < inSize ) {
                len++;
                if( v ) {
                    inTemp[ i ] = (unsigned char) (v - 1);
                }
            }
            else {
                inTemp[i] = 0;
            }
        }
        if( len ) {
            decodeblock( inTemp, outTemp );
            for( i = 0; i < len - 1; i++ ) {
	      if (outIndex >= iTempSize)
		{
		  bufTemp = (unsigned char *)realloc(bufTemp, iTempSize + 1024);
		  iTempSize += 1024;
		}
	      bufTemp[outIndex] = outTemp[i];
	      outIndex++;
            }
        }
    }
    
    *bufOut = bufTemp;
    *outSize = outIndex;
    if (NULL == bufTemp)
      return FALSE;
    else
      return TRUE;
}

/////////////////////////////////////////////////////////////
//
// ASCII character string to character value translation
//
/////////////////////////////////////////////////////////////

int ctocval(unsigned char cIn, unsigned char *val, int radix)
{
  char c;

  if (NULL == val)
    return FALSE;

  c = toupper(cIn);
  if (('0' <= c) &&
      ('9' >= c))
    *val = (c - '0');
  else if (('A' <= c) &&
	   ('F' >= c) &&
	   (16 == radix))
    *val = (c - 'A') + 10;
  else
    return FALSE;

  return TRUE;  
}

// Crappy substitute function for pleasant function that returned a short
// (now string to 2 char array) BUT it assures no endianness crap
int ip_strto2c(unsigned char* strToTranslate, unsigned char* c2Returned, int radix)
{
  int i = 0;
  int iLen = 0;
  unsigned short int sAns = 0;
  unsigned char cTemp = 0;
  unsigned char c2Ans[2];

  // Check for null pointers
  if ((NULL == strToTranslate) ||
      (NULL == c2Returned))
    return FALSE;

  // Right now, I'm only interested in supporting decimal and hex
  if ((16 != radix) &&
      (10 != radix))
    return FALSE;

  iLen = strlen((char*) strToTranslate);
  if ((0 >= iLen) ||
    (iLen > 5))
    return FALSE;

  for (i = 0; i < iLen; i++)
    {
      sAns = sAns * radix;
      if (FALSE == ctocval(strToTranslate[i], &cTemp, radix))
	return FALSE;
      sAns += cTemp;
    }

  memset(c2Ans, 0, 2);
  c2Ans[1] = (unsigned char) (sAns % 0x100);
  sAns = sAns / 0x100;
  c2Ans[0] = (unsigned char) sAns;

  memcpy(c2Returned, c2Ans, 2);
  return TRUE;
}

int ip_strtoc(unsigned char* strToTranslate, unsigned char* cReturned, int radix)
{
  int i = 0;
  int iLen = 0;
  unsigned char cAns = 0;
  unsigned char cTemp = 0;

  // Check for null pointers
  if ((NULL == strToTranslate) ||
      (NULL == cReturned))
    return FALSE;

  // Right now, I'm only interested in supporting decimal and hex
  if ((16 != radix) &&
      (10 != radix))
    return FALSE;

  iLen = strlen((char*) strToTranslate);
  if ((0 >= iLen) ||
    (iLen > 3))
    return FALSE;

  for (i = 0; i < iLen; i++)
    {
      cAns = cAns * radix;
      if (FALSE == ctocval(strToTranslate[i], &cTemp, radix))
	return FALSE;
      cAns += cTemp;
    }
  
  *cReturned = cAns;
  return TRUE;
}

/////////////////////////////////////////////////////////////
//
// Functions to calculate trailing bits in octet strings that
//  represent bit strings
//
/////////////////////////////////////////////////////////////

int calculatePrefixVals(int iPrefix, unsigned char* cBadTrailingBits, int* iGoodLeadingBytes)
{
  int iFullBytes = 0;
  unsigned char cGoodTrailingBits = 0;

  // Check for null pointers
  if ((NULL == cBadTrailingBits) ||
      (NULL == iGoodLeadingBytes))
    return FALSE;

  iFullBytes = iPrefix / 8;
  cGoodTrailingBits = (char) iPrefix % 8;
  if (0 != cGoodTrailingBits)
    {
      *cBadTrailingBits = 8 - cGoodTrailingBits;
      iFullBytes++;
    }
  else
    *cBadTrailingBits = 0;

  *iGoodLeadingBytes = iFullBytes;
  return TRUE;
}

int calculateAndClearPrefix(int iPrefix, int iSize, unsigned char* iparray,
			    unsigned char* cBadBits, int* iGoodBytes)
{
  int i = 0;
  int iIndex = 0;
  int iRemainder = 0;
  int iShift = 0;

    // Check for null pointers
  if ((NULL == cBadBits) ||
      (NULL == iGoodBytes) ||
      (NULL == iparray))
    return FALSE;

  for (i = iSize; iPrefix < i; i--)
    {
      iIndex = (i - 1)/8;
      iRemainder = i % 8;
      if (0 == iRemainder)
	iShift = iRemainder;
      else
	iShift = 8 - iRemainder;

      // DER encoding demands that we zero all unused trailing bits
      iparray[iIndex] &= ~(0x01 << iShift);
    }
  return calculatePrefixVals(iPrefix, cBadBits, iGoodBytes);
}

int calculateAndClearMM(int iIsMin, int iSize, unsigned char* iparray,
			unsigned char* cBadTrailingBits, int* iGoodLeadingBytes)
{
  int i = 0;
  int iIndex = 0;
  int iRemainder = 0;
  int iShift = 0;
  char cBitwiseCheck = 0;

    // Check for null pointers
  if ((NULL == cBadTrailingBits) ||
      (NULL == iGoodLeadingBytes) ||
      (NULL == iparray))
    return FALSE;

  for (i = iSize; 0 < i; i--)
    {
      iIndex = (i - 1)/8;
      iRemainder = i % 8;
      if (0 == iRemainder)
	iShift = iRemainder;
      else
	iShift = 8 - iRemainder;
      cBitwiseCheck = iparray[iIndex] & (0x01 << iShift);
      if (TRUE == iIsMin)
	{
	  if (0 != cBitwiseCheck)
	    break;
	}
      else if (FALSE == iIsMin)
	{
	  if (0 == cBitwiseCheck)
	    break;
	  else
	    // DER encoding demands that we zero all unused trailing bits
	    iparray[iIndex] &= ~(0x01 << iShift);
	}
    }
  return calculatePrefixVals(i, cBadTrailingBits, iGoodLeadingBytes);
}

/////////////////////////////////////////////////////////////
//
// IP Address octet strings from ASCII strings
//
/////////////////////////////////////////////////////////////

// Translation of dotted decimal IPv4 addresses
//
// JFG - Note: Currently handled by this function are addresses of the format
// 168.156/24, which may not be canonical, but which interprets out to
// 168.156.0.0/24 for now.
int translateIPv4Prefix(unsigned char* ipstring, unsigned char** ipbytearray, int* iprefixlen)
{
  int i = 0;
  int iStringLen = 0;
  int iByteIndex = 0;
  int iTempIndex = 0;
  int iRes = 0;
  unsigned char cAddrPart = 0;
  unsigned char cPrefix = 0;
  unsigned char cLastChar = 0;
  unsigned char cEmpty = 0;
  unsigned char stringtemp[4];
  unsigned char arraytemp[5];

  // Check for null pointers
  if ((NULL == ipstring) ||
      (NULL == *ipbytearray) ||
      (NULL == iprefixlen))
    return FALSE;

  // Max IPv4 Address Prefix
  iStringLen = strlen((char*) ipstring);
  if (19 < iStringLen)
    return ROA_INVALID;

  // Translate
  memset(stringtemp, 0, 4);
  memset(arraytemp, 0, 5);
  for (i = 0; (i < iStringLen) &&
	 (4 > iTempIndex); i++)
    {
      // The last couple of loops (after the prefix)
      if ('/' == cLastChar)
	{
	  stringtemp[iTempIndex] = ipstring[i];
	  iTempIndex++;
	  continue;
	}

      // Every loop before hitting the prefix (if it comes)
      if (('.' == ipstring[i]) ||
	  ('/' == ipstring[i]))
	{
	  // Validate the previous char (must have been numeric)
	  if (FALSE == ctocval(cLastChar, &cEmpty, 10))
	    return ROA_INVALID;

	  // Currently relying on strtoc to tell us if any
	  // of the characters in the string is untranslatable
	  iRes = (short int) ip_strtoc(stringtemp, &cAddrPart, 10);
	  if (FALSE == iRes)
	    return ROA_INVALID;
	  else
	    {
	      arraytemp[iByteIndex] = cAddrPart;
	      iByteIndex++;
	      iTempIndex = 0;
	      memset(stringtemp, 0, 4);
	    }
	}
      else
	{
	  stringtemp[iTempIndex] = ipstring[i];
	  iTempIndex++;
	}
      cLastChar = ipstring[i];
    }
  // If we got a badly formatted string at any point
  if (iTempIndex >= 4)
    return ROA_INVALID;

  // Translate the prefix
  // Currently relying on strtoc to tell us if any
  // of the characters in the string is untranslatable
  if ('/' == cLastChar)
    {
      iRes = ip_strtoc(stringtemp, &cPrefix, 10);
      if ((0 >= cPrefix) ||
	  (32 < cPrefix) ||
	  (FALSE == iRes))
	return ROA_INVALID;
    }
  // Or, if there was no prefix, finish the last
  // chunk tranlsation
  else
    {
      // Validate the previous char (must have been numeric)
      if (FALSE == ctocval(cLastChar, &cEmpty, 10))
	return ROA_INVALID;

      // Currently relying on strtoc to tell us if any
      // of the characters in the string is untranslatable
      iRes = (short int) ip_strtoc(stringtemp, &cAddrPart, 10);
      if (FALSE == iRes)
	return ROA_INVALID;
      else
	{
	  arraytemp[iByteIndex] = cAddrPart;
	  iByteIndex++;
	  iTempIndex = 0;
	  memset(stringtemp, 0, 4);
	}
      cPrefix = 32;
    }

  // Sanity check on number of copied bytes
  if (iByteIndex > 4)
    return ROA_INVALID;

  // Copy return values
  memcpy(*ipbytearray, arraytemp, 4);
  *iprefixlen = (int) cPrefix;

  return ROA_VALID;
}

// Translation of hexadecimal IPv6 addresses
//
int translateIPv6Prefix(unsigned char* ipstring, unsigned char** ipbytearray, int* iprefixlen)
{
  int i = 0;
  int iStringLen = 0;
  int iByteIndex = 0;
  int iTempIndex = 0;
  int iColonCount = 0;
  int iSkippedBytes = 0;
  int iRes = 0;
  int iLoopStart = 0;
  int iPrefixMark = 0;

  unsigned char cPrefix = 0;
  unsigned char cLastChar = 0;
  unsigned char cEmpty = 0;
  unsigned char stringtemp[5];
  unsigned char arraytemp[17];
  unsigned char cAddrPartArray[2];

  // Check for null pointers
  if ((NULL == ipstring) ||
      (NULL == *ipbytearray) ||
      (NULL == iprefixlen))
    return FALSE;

  // Max IPv6 Address Prefix
  iStringLen = strlen((char*) ipstring);
  if (43 < iStringLen)
    return ROA_INVALID;

  // First, find out how much skipping was done in the address
  //  and find the location of the prefix;
  iPrefixMark = 0;
  for (i = 0; i < iStringLen; i++)
    {
      if ('/' == ipstring[i])
	iPrefixMark = i;
      if (':' == ipstring[i])
	iColonCount++;
      cLastChar = ipstring[i];
    }
  if (0 == iPrefixMark)
    iPrefixMark = iStringLen;

  // If we start or finish with a colon (presumably paired)
  // we skipped an extra pair of bytes
  if ((':' == ipstring[0]) && (':' == ipstring[1]))
    {
      iColonCount--;
      iLoopStart = 1;
      cLastChar = ':';
    }
  if ((':' == ipstring[iPrefixMark - 1]) && (':' == ipstring[iPrefixMark - 2]))
    iColonCount--;

  // There can only be a maximum of 7 colons in any IPv6 address
  if (7 < iColonCount)
    return ROA_INVALID;

  // Then, translate
  memset(stringtemp, 0, 5);
  memset(arraytemp, 0, 17);
  for (i = iLoopStart; (i < iStringLen) &&
	 (5 > iTempIndex); i++)
    {
      // Tight prefix loop:
      // The last couple of loops (after the prefix)
      if ('/' == cLastChar)
	{
	  stringtemp[iTempIndex] = ipstring[i];
	  iTempIndex++;
	  continue;
	}

      // Every loop before hitting the prefix (if it comes)
      if ((':' == ipstring[i]) ||
	  ('/' == ipstring[i]))
	{
	  if (':' != cLastChar)
	    {
	      // Validate the previous char (must have been hex)
	      if (FALSE == ctocval(cLastChar, &cEmpty, 16))
		return ROA_INVALID;

	      // Currently relying on strto2c to tell us if any
	      // of the characters in the string is untranslatable
	      memset(cAddrPartArray, 0, 2);
	      iRes = ip_strto2c(stringtemp, cAddrPartArray, 16);
	      if (FALSE == iRes)
		return ROA_INVALID;
	      else
		{
		  arraytemp[iByteIndex] = cAddrPartArray[0];
		  arraytemp[iByteIndex+1] = cAddrPartArray[1];
		  iByteIndex += sizeof(short int);
		  iTempIndex = 0;
		  memset(stringtemp, 0, 5);
		}
	    }
	  else if (':' == ipstring[i])
	    {
	      iSkippedBytes = (8 - iColonCount) * 2;
	      memset(&(arraytemp[iByteIndex]), 0, iSkippedBytes);
	      iByteIndex += iSkippedBytes;
	    }
	  else
	    {
	      // We've hit the '/' with a preceding ':'
	      // Time to exit into the tight prefix loop
	      cLastChar = ipstring[i];
	      continue;
	    }
	}
      else
	{
	  stringtemp[iTempIndex] = ipstring[i];
	  iTempIndex++;
	}
      cLastChar = ipstring[i];
    }

  // If we got a badly formatted string at any point
  if (iTempIndex >= 5)
    return ROA_INVALID;

  // Translate the prefix
  // Currently relying on strtos to tell us if any
  // of the characters in the string is untranslatable
  if ('/' == cLastChar)
    {
      iRes = ip_strtoc(stringtemp, &cPrefix, 10);
      if ((0 >= cPrefix) ||
	  (128 < cPrefix) ||
	  (FALSE == iRes))
	return ROA_INVALID;
    }
  // Or, if there was no prefix, finish the last
  // chunk tranlsation
  else if (':' != cLastChar)
    {
      // Validate the previous char (must have been hex)
      if (FALSE == ctocval(cLastChar, &cEmpty, 16))
	return ROA_INVALID;

      // Currently relying on strtos to tell us if any
      // of the characters in the string is untranslatable
      iRes = ip_strto2c(stringtemp, cAddrPartArray, 16);
      if (FALSE == iRes)
	return ROA_INVALID;
      else
	{
	  arraytemp[iByteIndex] = cAddrPartArray[0];
	  arraytemp[iByteIndex+1] = cAddrPartArray[1];
	  iByteIndex += sizeof(short int);
	  iTempIndex = 0;
	  memset(stringtemp, 0, 5);
	}
      cPrefix = 128;
    }
  else
    cPrefix = 128;

  // Sanity check on number of copied bytes
  if (iByteIndex != 16)
    return ROA_INVALID;

  // Copy return values
  memcpy(*ipbytearray, arraytemp, 16);
  *iprefixlen = (int) cPrefix;

  return ROA_VALID;
}

/////////////////////////////////////////////////////////////
//
// Per-configuration item translation functions
//
/////////////////////////////////////////////////////////////

int setVersion(struct ROA* roa, unsigned char* versionstring)
{ 
  int iRes = 0;
  int iLen = 0;
  int iVersion = 0;

  // Because we only accept single-digit version numbers
  iLen = strlen((char*) versionstring);
  if (1 != iLen)
    return ROA_INVALID;

  // And all roas (for now) must be version 3
  iVersion = atoi((char*) versionstring);
  if (3 != iVersion)
    return ROA_INVALID;
  
  iRes = write_casn_num(&(roa->content.content.version.v3), iVersion);
  if (0 > iRes)
    return ROA_INVALID;

  iRes = write_casn_num(&(roa->content.content.signerInfos.signerInfo.version.v3), iVersion);
  if (0 > iRes)
    return ROA_INVALID;

  g_lastInstruction = NONE;
  return ROA_VALID;
}

int setSID(struct ROA* roa, unsigned char* sidstring)
{
  int iLen = 0;
  int sidIndex = 0;
  int stringIndex = 0;
  int iRes = 0;

  unsigned char cSIDPart = 0;
  unsigned char stringtemp[3];
  unsigned char sid[20];

  memset(sid, 0, 20);
  memset(stringtemp, 0, 3);

  // Because we only accept SKIs as SIDs
  // (xx:xx:(...16 more ...):xx:xx
  iLen = strlen((char*) sidstring);
  if (59 != iLen)
    return ROA_INVALID;

  // Read and translate SID, paired hex -> char
  sidIndex = 0;
  stringIndex = 0;
  while (sidIndex < 20)
    {
      memcpy(stringtemp, &sidstring[stringIndex], 2);
      // Currently relying on strtos to tell us if any
      // of the characters in the string is untranslatable
      iRes = ip_strtoc(stringtemp, &cSIDPart, 16);
      if (FALSE == iRes)
	return ROA_INVALID;
      else
	sid[sidIndex] = cSIDPart;
      stringIndex += 3;
      sidIndex++;
    }
  
  write_casn(&(roa->content.content.signerInfos.signerInfo.sid.subjectKeyIdentifier), sid, 20);
  g_lastInstruction = NONE;
  return ROA_VALID;
}

int setSignature(struct ROA* roa, unsigned char* signstring)
{
  int iLen = 0;

  // Length is whatever it is; we've already guaranteed it's not 512+ chars,
  // so we'll take what we've got
  iLen = strlen((char*) signstring);

  // Write the signature directly to the casn
  write_casn(&(roa->content.content.signerInfos.signerInfo.signature), signstring, iLen);
  g_lastInstruction = NONE;
  return ROA_VALID;
}

int setAS_ID(struct ROA* roa, unsigned char* asidstring)
{
  int iLen = 0;
  int iAS_ID = 0;

  // Because we only accept 0 < ASID < 65536
  iLen = strlen((char*) asidstring);
  if (5 < iLen)
    return ROA_INVALID;
  iAS_ID = atoi((char*) asidstring);
  if ((0 >= iAS_ID) ||
      (iAS_ID >= 65536))
    return ROA_INVALID;

  write_casn_num(&(roa->content.content.encapContentInfo.eContent.roa.asID), iAS_ID);
  g_lastInstruction = NONE;
  return ROA_VALID;
}

int setIPFamily(struct ROA* roa, unsigned char* ipfamstring)
{
  int iLen = 0;
  int iBlocks = 0;
  unsigned char familytemp[3];
  struct ROAIPAddressFamily *roaFamily = NULL;

  // Length must be 4 (i.e. IPvX)
  iLen = strlen((char*) ipfamstring);
  if (4 != iLen)
    return ROA_INVALID;

  memset(familytemp, 0, 3);
  
  // Set AFI string (first two bytes of familytemp should be
  //  0x00 0x0Z, where Z is determined by the family)
  //  after checking to make sure that each block occurs only
  //  once and in the proper order
  if (0 == strcmp(ianaAfiStrings[IPV4], (char*) ipfamstring))
    {
      if ((TRUE == g_iIPv4Flag) ||
	  (TRUE == g_iIPv6Flag))
	return ROA_INVALID;
      familytemp[1] = 0x01;
      g_lastInstruction = IPV4FAM;
      g_iIPv4Flag = TRUE;
    }
  else if (0 == strcmp(ianaAfiStrings[IPV6], (char*) ipfamstring))
    {
      if (TRUE == g_iIPv6Flag)
	return ROA_INVALID;
      familytemp[1] = 0x02;
      g_lastInstruction = IPV6FAM;
      g_iIPv6Flag = TRUE;
    }
  else
    return ROA_INVALID;

  // Write a new IP block directly to the casn
  iBlocks = num_items(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self));
  if (0 <= iBlocks)
    {
      // If that worked, fill it with the family info
      roaFamily = (struct ROAIPAddressFamily*) inject_casn(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), iBlocks);
      //roaFamily = (struct ROAIPAddressFamily*) member_casn(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), iBlocks);
      write_casn(&(roaFamily->addressFamily), familytemp, 2);
      return ROA_VALID;
    }
  return ROA_INVALID;
}

int setIPAddr(struct ROA* roa, unsigned char* ipaddrstring)
{
  unsigned char ipv4array[5];
  unsigned char ipv6array[17];
  unsigned char *arrayptr = NULL;
  int iPrefixSize = 0;
  int iGoodBytes = 0;
  unsigned char cBadBits = 0;
  int iRes = ROA_INVALID;
  int iBlocks = 0;
  int iAddrs = 0;
  struct ROAIPAddressFamily *roaFamily = NULL;

#ifdef IP_RANGES_ALLOWED
  struct IPAddressOrRangeA *roaAddr = NULL;
#else
  struct IPAddress *roaAddr = NULL;
#endif

  memset(ipv4array, 0, 5);
  memset(ipv6array, 0, 17);

  // First, translate the address into something meaningful
  if ((IPV4FAM == g_lastInstruction) ||
      (IPV4CONT == g_lastInstruction))
    {
      arrayptr = &ipv4array[1];
      iRes = translateIPv4Prefix(ipaddrstring, (unsigned char**) &arrayptr, &iPrefixSize);
    }
  else if ((IPV6FAM == g_lastInstruction) ||
	   (IPV6CONT == g_lastInstruction))
    {
      arrayptr = &ipv6array[1];
      iRes = translateIPv6Prefix(ipaddrstring, (unsigned char**) &arrayptr, &iPrefixSize);
    }
  else
    return ROA_INVALID;

  // If translation failed, we're done
  if (ROA_INVALID == iRes)
    return iRes;

  // Otherwise, write the data to the roa
  if ((IPV4FAM == g_lastInstruction) ||
      (IPV4CONT == g_lastInstruction))
    {
      // Pull valid leading bytes/invalid trailing bits out of the prefix
      //  (necessary to constuct ASN BITSTRING), then populate the bit notice
      //  and add one to the length of the array to be copied
      calculateAndClearPrefix(iPrefixSize, 32, arrayptr, &cBadBits, &iGoodBytes);
      ipv4array[0] = cBadBits;
      iGoodBytes++;
      // Then, write the bitstring (as an octet string) to the latest generated roaIPFam
      // after generating a new block for it
      iBlocks = num_items(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self));
      if (0 < iBlocks)
	{
	  roaFamily = (struct ROAIPAddressFamily*) member_casn(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), iBlocks - 1);
#ifdef IP_RANGES_ALLOWED
	  iAddrs = num_items(&(roaFamily->addressesOrRanges.self));
	  if (0 <= iAddrs)
	    {
	      roaAddr = (struct IPAddressOrRangeA*) inject_casn(&(roaFamily->addressesOrRanges.self), iAddrs);
	      write_casn(&(roaAddr->addressPrefix), ipv4array, iGoodBytes);
	    }
	  else
	    iRes = ROA_INVALID;
#else
	  iAddrs = num_items(&(roaFamily->addresses.self));
	  if (0 <= iAddrs)
	    {
	      roaAddr = (struct IPAddress*) inject_casn(&(roaFamily->addresses.self), iAddrs);
	      write_casn(roaAddr, ipv4array, iGoodBytes);
	    }
	  else
	    iRes = ROA_INVALID;
#endif
	}
      else
	iRes = ROA_INVALID;
      g_lastInstruction = IPV4CONT;
    }
  else if ((IPV6FAM == g_lastInstruction) ||
	   (IPV6CONT == g_lastInstruction))
    {
      // Pull valid leading bytes/invalid trailing bits out of the prefix
      //  (necessary to constuct ASN BITSTRING), then populate the bit notice
      //  and add one to the length of the array to be copied
      calculateAndClearPrefix(iPrefixSize, 128, arrayptr, &cBadBits, &iGoodBytes);
      ipv6array[0] = cBadBits;
      iGoodBytes++;
      // Then, write the bitstring (as an octet string) to the casn
      iBlocks = num_items(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self));
      if (0 < iBlocks)
	{
	  roaFamily = (struct ROAIPAddressFamily*) member_casn(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), iBlocks - 1);
#ifdef IP_RANGES_ALLOWED
	  iAddrs = num_items(&(roaFamily->addressesOrRanges.self));
	  if (0 <= iAddrs)
	    {
	      roaAddr = (struct IPAddressOrRangeA*) inject_casn(&(roaFamily->addressesOrRanges.self), iAddrs);
	      write_casn(&(roaAddr->addressPrefix), ipv6array, iGoodBytes);
	    }
	  else
	    iRes = ROA_INVALID;
#else
	  iAddrs = num_items(&(roaFamily->addresses.self));
	  if (0 <= iAddrs)
	    {
	      roaAddr = (struct IPAddress*) inject_casn(&(roaFamily->addresses.self), iAddrs);
	      write_casn(roaAddr, ipv6array, iGoodBytes);
	    }
	  else
	    iRes = ROA_INVALID;
#endif
	}
      else
	iRes = ROA_INVALID;
      g_lastInstruction = IPV6CONT;
    }

  return iRes;
}

// These two functions are only required if we allow ranges, with their
// min/max qualifiers
#ifdef IP_RANGES_ALLOWED

int setIPAddrMin(struct ROA* roa, unsigned char* ipaddrminstring)
{
  unsigned char ipv4array[5];
  unsigned char ipv6array[17];
  unsigned char *arrayptr = NULL;
  int iPrefixSize = 0;
  int iGoodBytes = 0;
  unsigned char cBadBits = 0;
  int iRes = ROA_INVALID;
  int iBlocks = 0;
  int iAddrs = 0;
  struct IPAddressOrRangeA *roaAddr = NULL;
  struct ROAIPAddressFamily *roaFamily = NULL;

  memset(ipv4array, 0, 5);
  memset(ipv6array, 0, 17);

  // First, translate the address into something meaningful
  if ((IPV4FAM == g_lastInstruction) ||
      (IPV4CONT == g_lastInstruction))
    {
      arrayptr = &ipv4array[1];
      iRes = translateIPv4Prefix(ipaddrminstring, (unsigned char**) &arrayptr, &iPrefixSize);
    }
  else if ((IPV6FAM == g_lastInstruction) ||
	   (IPV6CONT == g_lastInstruction))
    {
      arrayptr = &ipv6array[1];
      iRes = translateIPv6Prefix(ipaddrminstring, (unsigned char**) &arrayptr, &iPrefixSize);
    }
  else
    return ROA_INVALID;

  // If translation failed, or if we got anything other than
  // a single address, we're done
  if ((ROA_INVALID == iRes) ||
      (32 != iPrefixSize))
    return iRes;

  // Otherwise, write the data to the roa
  if ((IPV4FAM == g_lastInstruction) ||
      (IPV4CONT == g_lastInstruction))
    {
      // Construct ASN BITSTRING under the assumption that we have a
      // minimum address which needs paring down
      calculateAndClearMM(TRUE, 32, arrayptr, &cBadBits, &iGoodBytes);
      ipv4array[0] = cBadBits;
      iGoodBytes++;

      // Then, write the bitstring (as an octet string) to the casn
      iBlocks = num_items(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self));
      if (0 < iBlocks)
	{
	  roaFamily = (struct ROAIPAddressFamily*) member_casn(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), iBlocks - 1);
	  iAddrs = num_items(&(roaFamily->addressesOrRanges.self));
	  if (0 <= iAddrs)
	    {
	      roaAddr = (struct IPAddressOrRangeA*) inject_casn(&(roaFamily->addressesOrRanges.self), iAddrs);
	      write_casn(&(roaAddr->addressRange.min), ipv4array, iGoodBytes);
	    }
	  else
	    iRes = ROA_INVALID;
	}
      else
	iRes = ROA_INVALID;
      g_lastInstruction = IPV4MIN;
    }
  else if ((IPV6FAM == g_lastInstruction) ||
	   (IPV6CONT == g_lastInstruction))
    {
      // Construct ASN BITSTRING under the assumption that we have a
      // minimum ipv6 address which needs paring down
      calculateAndClearMM(TRUE, 128, arrayptr, &cBadBits, &iGoodBytes);
      ipv6array[0] = cBadBits;
      iGoodBytes++;

      // Then, write the bitstring (as an octet string) to the casn
      iBlocks = num_items(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self));
      if (0 < iBlocks)
	{
	  roaFamily = (struct ROAIPAddressFamily*) member_casn(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), iBlocks - 1);
	  iAddrs = num_items(&(roaFamily->addressesOrRanges.self));
	  if (0 <= iAddrs)
	    {
	      roaAddr = (struct IPAddressOrRangeA*) inject_casn(&(roaFamily->addressesOrRanges.self), iAddrs);
	      // roaAddr = (struct IPAddressOrRangeA*) member_casn(&(roaFamily->addressesOrRanges.self), iAddrs);
	      write_casn(&(roaAddr->addressRange.min), ipv6array, iGoodBytes);
	    }
	  else
	    iRes = ROA_INVALID;
	}
      else
	iRes = ROA_INVALID;
      g_lastInstruction = IPV6MIN;
    }

  return iRes;
}

int setIPAddrMax(struct ROA* roa, unsigned char* ipaddrmaxstring)
{
  unsigned char ipv4array[5];
  unsigned char ipv6array[17];
  unsigned char *arrayptr = NULL;
  int iPrefixSize = 0;
  int iGoodBytes = 0;
  unsigned char cBadBits = 0;
  int iRes = ROA_INVALID;
  int iBlocks = 0;
  int iAddrs = 0;
  struct IPAddressOrRangeA *roaAddr = NULL;
  struct ROAIPAddressFamily *roaFamily = NULL;

  memset(ipv4array, 0, 5);
  memset(ipv6array, 0, 17);

  // First, translate the address into something meaningful
  if (IPV4MIN == g_lastInstruction)
    {
      arrayptr = &ipv4array[1];
      iRes = translateIPv4Prefix(ipaddrmaxstring, (unsigned char**) &arrayptr, &iPrefixSize);
    }
  else if (IPV6MIN == g_lastInstruction)
    {
      arrayptr = &ipv6array[1];
      iRes = translateIPv6Prefix(ipaddrmaxstring, (unsigned char**) &arrayptr, &iPrefixSize);
    }
  else
    return ROA_INVALID;

  // If translation failed, or if we got anything other than
  // a single address, we're done
  if ((ROA_INVALID == iRes) ||
      (32 != iPrefixSize))
    return iRes;

  // Otherwise, write the data to the roa
  if (IPV4MIN == g_lastInstruction)
    {
      // Construct ASN BITSTRING under the assumption that we have a
      // maximum ipv4 address which needs paring down
      calculateAndClearMM(FALSE, 32, arrayptr, &cBadBits, &iGoodBytes);
      ipv4array[0] = cBadBits;
      iGoodBytes++;

      // Then, write the bitstring (as an octet string) to the casn
      iBlocks = num_items(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self));
      if (0 < iBlocks)
	{
	  roaFamily = (struct ROAIPAddressFamily*) member_casn(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), iBlocks - 1);
	  iAddrs = num_items(&(roaFamily->addressesOrRanges.self));
	  if (0 < iAddrs)
	    {
	      roaAddr = (struct IPAddressOrRangeA*) member_casn(&(roaFamily->addressesOrRanges.self), iAddrs - 1);
	      write_casn(&(roaAddr->addressRange.max), ipv4array, iGoodBytes);
	    }
	  else
	    iRes = ROA_INVALID;
	}
      else
	iRes = ROA_INVALID;
      g_lastInstruction = IPV4CONT;
    }
  else if (IPV6MIN == g_lastInstruction)
    {
      // Construct ASN BITSTRING under the assumption that we have a
      // maximum ipv6 address which needs paring down
      calculateAndClearMM(FALSE, 128, arrayptr, &cBadBits, &iGoodBytes);
      ipv6array[0] = cBadBits;
      iGoodBytes++;

      // Then, write the bitstring (as an octet string) to the casn
      iBlocks = num_items(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self));
      if (0 < iBlocks)
	{
	  roaFamily = (struct ROAIPAddressFamily*) member_casn(&(roa->content.content.encapContentInfo.eContent.roa.ipAddrBlocks.self), iBlocks - 1);
	  iAddrs = num_items(&(roaFamily->addressesOrRanges.self));
	  if (0 < iAddrs)
	    {
	      roaAddr = (struct IPAddressOrRangeA*) member_casn(&(roaFamily->addressesOrRanges.self), iAddrs - 1);
	      write_casn(&(roaAddr->addressRange.max), ipv6array, iGoodBytes);
	    }
	  else
	    iRes = ROA_INVALID;
	}
      else
	iRes = ROA_INVALID;
      g_lastInstruction = IPV6CONT;
    }

  return iRes;
}

#endif // IP_RANGES_ALLOWED

int setCertName(struct ROA* roa, unsigned char* certfilenamestring)
{
  int iLen = 0;
  int iRet = 0;
  int iCerts = 0;

  // JFG - Do we have a filename max, given our restriction to < 512?
  iLen = strlen((char*) certfilenamestring);

  // Check to make sure there's only one cert and it's the one
  //  we're about to read in.
  iCerts = num_items(&(roa->content.content.certificates.self));
  if (0 != iCerts)
    return ROA_INVALID;

  // Get the cert read in
  if (NULL != inject_casn(&(roa->content.content.certificates.self), 0))
    iRet = get_casn_file(&(roa->content.content.certificates.certificate.self), (char*) certfilenamestring, 0);
  g_lastInstruction = NONE;

  if (iRet > 0)
    return ROA_VALID;
  else
    return ROA_INVALID;
}

/////////////////////////////////////////////////////////////
//
// General config file (.cnf) interpretation function
//
/////////////////////////////////////////////////////////////

int confInterpret(char* filename, struct ROA* roa)
{
  char line[MAX_LINE + 1] = "";
  char key[MAX_LINE + 1] = "";
  unsigned char value[MAX_LINE + 1] = "";

  int iRet = 0;
  int iRet2 = 0;
  int iROAState = ROA_VALID;
  int iLineCount = 0;
  FILE* fp = NULL;
  enum configKeys ck = 0;

  // Acting as bools; testing for required config params
  int iConfiguredKey[CONFIG_KEY_MAX];
  
  for (ck = VERSION; ck < CONFIG_KEY_MAX; ck++)
    iConfiguredKey[ck] = FALSE;

  fp = fopen(filename, "r");
  if (NULL == fp)
    {
      // Error
      printf("Error opening file %s\n", filename);
      return ROA_INVALID;
    }

  // Initialize globals
  g_lastInstruction = NONE;
  g_iIPv4Flag = FALSE;
  g_iIPv6Flag = FALSE;

  // Read, line by line, into the struct
  while ((EOF != iRet) && (ROA_VALID == iROAState))
    {
      iLineCount++;
      memset(line, 0, MAX_LINE + 1);
      // See warning at top of file about hardcoded "512"
      iRet = fscanf(fp, "%512[^\n]%*1c", line);
      if (0 == iRet)
	{
	  getc(fp);
	  continue;
	}
      if (1 == iRet)
	{
	  memset(key, 0, MAX_LINE + 1);
	  memset(value, 0, MAX_LINE + 1);
	  if ('#' == line[0])
	      continue;
	  if ('[' == line[0])
	      continue;
	  iRet2 = sscanf(line, "%s%*[ \t]%*[=]%*[ \t]%s", key, value);
	  if (2 != iRet2)
	    {
	      printf("Error parsing line %d\n", iLineCount);
	      iROAState = ROA_INVALID;
	    }
	  else
	    {
	      for (ck = VERSION; ck < CONFIG_KEY_MAX; ck++)
		{
		  iRet2 = strcmp(configKeyStrings[ck], key);
		  if (0 == iRet2)
		    break;
		}

	      switch(ck)
		{
		case VERSION:
		  if ((isInstructionForcing(g_lastInstruction)) ||
		      (TRUE == iConfiguredKey[ck]))
		    {
		      iRet2 = ROA_INVALID;
		      break;
		    }
		  iRet2 = setVersion(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
		case SID:
		  if ((isInstructionForcing(g_lastInstruction)) ||
		      (TRUE == iConfiguredKey[ck]))
		    {
		      iRet2 = ROA_INVALID;
		      break;
		    }
		  iRet2 = setSID(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
		case SIGNATURE:
		  // JFG - In the real world, we're going to calculate this
		  //  instead of getting it from a file
		  if ((isInstructionForcing(g_lastInstruction)) ||
		      (TRUE == iConfiguredKey[ck]))
		    {
		      iRet2 = ROA_INVALID;
		      break;
		    }
		  iRet2 = setSignature(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
		case AS_ID:
		  if ((isInstructionForcing(g_lastInstruction)) ||
		      (TRUE == iConfiguredKey[ck]))
		    {
		      iRet2 = ROA_INVALID;
		      break;
		    }
		  iRet2 = setAS_ID(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
		case IPFAM:
		  if (isInstructionForcing(g_lastInstruction))
		    {
		      iRet2 = ROA_INVALID;
		      break;
		    }
		  iRet2 = setIPFamily(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
		case IPADDR:
		  // Check for valid previous instruction
		  // resides in subfunction
		  iRet2 = setIPAddr(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
#ifdef IP_RANGES_ALLOWED
		case IPADDRMIN:
		  // Check for valid previous instruction
		  // resides in subfunction
		  iRet2 = setIPAddrMin(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
		case IPADDRMAX:
		  // Check for valid previous instruction
		  // resides in subfunction
		  iRet2 = setIPAddrMax(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
#endif // IP_RANGES_ALLOWED
		case CERTNAME:
		  if ((isInstructionForcing(g_lastInstruction)) ||
		      (TRUE == iConfiguredKey[ck]))
		    {
		      iRet2 = ROA_INVALID;
		      break;
		    }
		  iRet2 = setCertName(roa, value);
		  iConfiguredKey[ck] = TRUE;
		  break;
		case CONFIG_KEY_MAX:
		default:
		  printf("Unknown key on line %d\n", iLineCount);
		  iROAState = ROA_INVALID;
		  break;
		}

	      if (ROA_INVALID == iRet2)
		{
		  printf("Unparseable value or unexpected key on line %d\n", iLineCount);
		  iROAState = ROA_INVALID;
		}
	      // JFG - Debugging code
	      // printf("The value of key %s(%d) is %s\n", key, ck, value);
	    }
	}
    }

  // If we didn't finish an IP address block (uh-oh!)
  if (isInstructionForcing(g_lastInstruction))
    {
      printf("Unfinished IP block before line %d\n", iLineCount);
      iROAState = ROA_INVALID;
    }

  // If we didn't have one of the required parameters
  for (ck = VERSION; ck < CONFIG_KEY_MAX; ck++)
    {
      if (FALSE == iConfiguredKey[ck])
	{
	  if ((SID == ck) ||
	      (SIGNATURE == ck) ||
	      (AS_ID == ck) ||
	      (IPFAM == ck))
	    {
	      printf("Missing required key %s\n", configKeyStrings[ck]);
	      iROAState = ROA_INVALID;
	    }
	}
    }

  iRet = fclose(fp);
  return iROAState;
}

/////////////////////////////////////////////////////////////
//
// Exported functions from roa_utils.h
//
/////////////////////////////////////////////////////////////

int roaFromFile(char *fname, int fmt, int doval, struct ROA **rp)
{
  int iROAState = 0;
  int iReturn = TRUE;
  int fd = 0;
  int iSize, iSizeFinal, iSizeTmp = 0;
  unsigned char *buf, *buf_final, *buf_tmp = NULL;
  struct AlgorithmIdentifier *algorithmID = NULL;
  struct SignerInfo* signerInfo = NULL;

  // Parameter validity checks
  if (NULL == fname)
    return FALSE;

  *rp = (struct ROA*) malloc(sizeof(struct ROA));
  if (NULL == *rp)
    {
      // Error
      printf("Error malloc'ing memory for ROA\n");
      return FALSE;
    }

  // No return value; must assume success
  ROA(*rp, 0);

  // This write _must_ be done before the injections
  write_objid(&((*rp)->contentType), id_signedData);

  // JFG - Consider injecting these on a per-struct basis just in case
  //  there's a requirements revision.
  algorithmID = (struct AlgorithmIdentifier*) inject_casn(&((*rp)->content.content.digestAlgorithms.self), 0);
  signerInfo = (struct SignerInfo*) inject_casn(&((*rp)->content.content.signerInfos.self), 0);
  if ((NULL == algorithmID) ||
      (NULL == signerInfo))
    {
      free(*rp);
      return FALSE;
    }
  
  // Fill default algorithm slots
  write_objid(&(algorithmID->algorithm), id_sha256);
  write_objid(&((*rp)->content.content.encapContentInfo.eContentType), routeOriginAttestation);
  write_objid(&(signerInfo->digestAlgorithm.algorithm), id_sha256);
  write_objid(&(signerInfo->signatureAlgorithm.algorithm), id_sha_256WithRSAEncryption);

  // Open the file and read in its contents
  if ((fd = open(fname, (O_RDONLY))) < 0)
    {
      delete_casn(&((*rp)->self));
      return FALSE;
    }
  iSize = 1024;
  buf = buf_tmp = (unsigned char *)calloc(1, iSize);
  while ( 1 )
    {
      if ((iSizeTmp = read(fd, buf_tmp, 1024)) == 1024)
	{
	  buf = (unsigned char *)realloc(buf, iSize + 1024);
	  buf_tmp = &buf[iSize];
	  iSize += 1024;
	}
      else if (iSizeTmp < 0)
	{
	  close(fd);
	  delete_casn(&((*rp)->self));
	  return FALSE;
	}
      else
	break;
    }
  close(fd);
  iSize = (iSize - 1024 + iSizeTmp);
  buf_final = buf;
  iSizeFinal = iSize;

  switch(fmt)
    {
    case FMT_PEM:
      // Decode buffer from b64, skipping unnecessary chars
      buf_final = NULL;
      iReturn = decode_b64(buf, iSize, &buf_final, &iSizeFinal);
      // IMPORTANT: NO break, control falls through
    case FMT_DER:      
      iSizeTmp = decode_casn(&((*rp)->self), buf_final);
      if (buf_final != buf)
	free(buf);
      free(buf_final);
      if (iSizeTmp != iSizeFinal)
	{
	  delete_casn(&((*rp)->self));
	  iReturn = FALSE;
	}
      else
	iReturn = TRUE;
      // iReturn = get_casn_file(&((*rp)->self), fname, 0);
      break;
    case FMT_CONF:
      iROAState = confInterpret(fname, *rp);
      if (ROA_INVALID == iROAState)
	{
	  delete_casn(&((*rp)->self));
	  iReturn = FALSE;
	}
      break;
    default:
      iReturn = FALSE;
      break;
    }

  // JFG - Put back in when the validate function is finished
  //if ((TRUE == iReturn) && (TRUE == doval))
  //  iReturn = roaValidate(*rp);
  return iReturn;
}

int roaToFile(struct ROA *r, char *fname, int fmt)
{
  int fd = 0;
  int iReturn = TRUE;
  int iSizeDER, iSizePEM = 0;
  unsigned char *buf_der, *buf_pem = NULL;
  //int iCASNSize = 0;
  //char *casn = 0;

  // Parameter validity checks
  if (NULL == fname)
    return FALSE;

  /*
  // JFG - Debugging code; leave out unless required
  iCASNSize = dump_size(&(r->self));
  if (0 > iCASNSize)
    return FALSE;
  casn = malloc(iCASNSize);
  if (NULL == casn)
    return FALSE;
  dump_casn(&(r->self), casn);
  printf("%s", casn);
  free(casn);
  */

  // Encode CASN
  if ((fd = open(fname, (O_WRONLY | O_CREAT | O_TRUNC), 0777)) < 0)
    return FALSE;
  if ((iSizeDER = size_casn(&(r->self))) < 0)
    {
      close(fd);
      return FALSE;
    }
  buf_der = (unsigned char *)calloc(1, iSizeDER);
  encode_casn(&(r->self), buf_der);

  switch(fmt)
    {
    case FMT_PEM:
      // JFG - Ask what length PEM file lines expect to be
      //  (right now, hardcoded to 50)
      iReturn = encode_b64(buf_der, iSizeDER, &buf_pem, &iSizePEM, 50);

      // Write to file
      if (TRUE == iReturn)
	{
	  iReturn = write(fd, buf_pem, iSizePEM);
	  free(buf_pem);
	}
      free(buf_der);
      close(fd);
      if (iSizePEM != iReturn)
	iReturn = FALSE;
      else
	iReturn = TRUE;

      break;
    case FMT_DER:
      // Write to file
      iReturn = write(fd, buf_der, iSizeDER);
      free(buf_der);
      close(fd);
      if (iSizeDER != iReturn)
	iReturn = FALSE;
      else
	iReturn = TRUE;
      // iReturn = put_casn_file(&(r->self), fname, 0);
      break;
    case FMT_CONF:
      // NOT OUR CONCERN RIGHT NOW
      // NO NEED TO DO THIS.
      break;
    default:
      iReturn = FALSE;
      break;
    }

  return iReturn;
}
