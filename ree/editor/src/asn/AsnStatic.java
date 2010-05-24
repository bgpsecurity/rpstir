/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE—RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

// char sfcsid[] = "@(#)AsnStatic.java 732E"
package asn;

public class AsnStatic
{
    public static final short ASN_MATCH_ERR      = 1;
    public static final short ASN_MEM_ERR        = 2;
    public static final short ASN_GEN_ERR        = 3;
    public static final short ASN_CHOICE_ERR     = 4;
    public static final short ASN_OF_ERR         = 5;
    public static final short ASN_MANDATORY_ERR  = 6;
    public static final short ASN_NOT_OF_ERR     = 7;
    public static final short ASN_OF_BOUNDS_ERR  = 8;
    public static final short ASN_EMPTY_ERR      = 9;
    public static final short ASN_DEFINER_ERR    = 10;
    public static final short ASN_NO_DEF_ERR     = 11;
    public static final short ASN_BOUNDS_ERR     = 12;
    public static final short ASN_TYPE_ERR       = 13;
    public static final short ASN_TIME_ERR       = 14;
    public static final short ASN_CODING_ERR     = 15;
    public static final short ASN_NULL_PTR       = 16;
    public static final short ASN_NONE_ERR       = 17;
    public static final short ASN_UNDEF_VALUE    = 18;
    public static final short ASN_NO_CHOICE_ERR  = 19;
    public static final short ASN_MASK_ERR       = 20;
    public static final short ASN_DEFINED_ERR    = 21;
    public static final short ASN_LENGTH_ERR     = 22;
    public static final short ASN_FILE_ERR       = 23;
    public static final short ASN_CONSTRAINT_ERR = 24;
    public static final short ASN_RECURSION_ERR  = 25;
    public static final short ASN_MAX_ERR_NUM    = ASN_RECURSION_ERR;

    public static final String[] errorMsg =
        {
	"",
	"Stream doesn't match object",
	"Error getting memory",
	"Error in AsnStatic.ASN_gen's code",
	"Can't write to a CHOICE",
	"Tags not consistent in SET/SEQ OF",
	"Mandatory field is not filled in",
	"Not a SET/SEQ OF",
	"Out of bounds in SET/SEQ OF",
	"Source is empty",
	"Definer not in table",
	"DEFINED BY not defined yet",
	"Size out of bounds",
	"Invalid operation for this type",
	"Invalid time field",
	"Improper ASN.1 string",
	"Null pointer passed to AsnObj member function",
	"Can't write to a NONE",
	"Trying to write an undefined value",
	"Character string not valid for any of CHOICE",
	"Invalid character at [-(value returned)]",
	"Error trying to find DEFINED BY",
	"Invalid length field",
	"Didn't use all of file",
	"Failed constraint test",
	"Constraint calls forbidden function",
        };

    public static String getErrorMsg(int errorNum)
        {
	if (errorNum == 0 || errorNum > AsnStatic.ASN_MAX_ERR_NUM)
            return ("Unknown error");
	return (AsnStatic.errorMsg[errorNum]);
	}
    
    public static final short ASN_FILLED_FLAG     = 1;
    public static final short ASN_POINTER_FLAG    = 2;
    public static final short ASN_OPTIONAL_FLAG   = 4;
    public static final short ASN_OF_FLAG         = 8;
    public static final short ASN_FALSE_FLAG      = 0x20;   // asn_jen only
    public static final short ASN_SUB_INDEF_FLAG  = 0x20;   // java only
    public static final short ASN_TABLE_FLAG      = 0x40;
    public static final short ASN_DUPED_FLAG      = 0x80;
    public static final short ASN_CONSTRAINT_FLAG = 0x100;
    public static final short ASN_DEFAULT_FLAG    = 0x200;
    public static final short ASN_DEFINED_FLAG    = 0x800;
    public static final short ASN_CHOSEN_FLAG     = 0x1000;
    public static final short ASN_DEFINER_FLAG    = 0x1000;
    public static final short ASN_EXPORT_FLAG     = 0x2000;
    public static final short ASN_INDEF_LTH_FLAG  = 0x2000;
    public static final short ASN_EXPLICIT_FLAG   = 0x4000;
    public static final int   ASN_ENUM_FLAG       = 0x8000;
    
    public static final short ASN_NUMERIC_MASK   = 1;
    public static final short ASN_PRINTABLE_MASK = 4;
    public static final short ASN_T61_MASK       = 8;
    public static final short ASN_IA5_MASK       = 0x10;

    public static final short BOOL_DEFAULT       = 1;
    public static final short BOOL_DEFINED       = 2;
    public static final short BOOL_DEFINED_VAL   = 4;

    public static final short ASN_BOOL_FALSE     = 0x00;
    public static final short ASN_BOOL_TRUE      = 0xFF;

    public static final short ccitt = 0;
    public static final short itu_t = 0;
    public static final short iso = 1;
    public static final short joint_ios_ccitt = 2;
    public static final short joint_iso_itu_t = 2;
    public static final short standard = 0;
    public static final short member_body = 2;
    public static final short identified_organization = 3;
    
    public static final short ASN_READING = 1;
    public static final short ASN_RE_SIZING = 2;
    public static final short ASN_RE_READING = 3;
    
    public static final short ASN_ANY              = 0;
    public static final short ASN_BOOLEAN          = 1;
    public static final short ASN_INTEGER          = 2;
    public static final short ASN_BITSTRING        = 3;
    public static final short ASN_OCTETSTRING      = 4;
    public static final short ASN_NULL             = 5;
    public static final short ASN_OBJ_ID           = 6;
    public static final short ASN_EXTERNAL         = 8;
    public static final short ASN_REAL             = 9;
    public static final short ASN_ENUMERATED       = 0x0A;
    public static final short ASN_UTF8_STRING      = 0x0C;
    public static final short ASN_NUMERIC_STRING   = 0x12;
    public static final short ASN_PRINTABLE_STRING = 0x13;
    public static final short ASN_T61_STRING       = 0x14;
    public static final short ASN_VIDEOTEX_STRING  = 0x15;
    public static final short ASN_IA5_STRING       = 0x16;
    public static final short ASN_UTCTIME          = 0x17;
    public static final short ASN_GENTIME          = 0x18;
    public static final short ASN_GRAPHIC_STRING   = 0x19;
    public static final short ASN_VISIBLE_STRING   = 0x1A;
    public static final short ASN_GENERAL_STRING   = 0x1B;
    public static final short ASN_UNIVERSAL_STRING = 0x1C;
    public static final short ASN_BMP_STRING       = 0x1E;
    public static final short ASN_XT_TAG           = 0x1F;
    public static final short ASN_CONSTRUCTED      = 0x20;
    public static final short ASN_INSTANCE_OF      = 0x28;
    public static final short ASN_SEQUENCE         = 0x30;
    public static final short ASN_SET              = 0x31;
    public static final short ASN_APPL_SPEC        = 0x40;
    public static final short ASN_APPL_CONSTR   =   (ASN_APPL_SPEC | ASN_CONSTRUCTED);
    public static final short ASN_CONT_SPEC     =   0x80;
    public static final short ASN_CONT_CONSTR   =   (ASN_CONT_SPEC | ASN_CONSTRUCTED);
    public static final short ASN_PRIV_SPEC     =   0xC0;
    public static final short ASN_PRIV_CONSTR   =   (ASN_PRIV_SPEC | ASN_CONSTRUCTED);
    public static final short ASN_INDEF_LTH     =   0x80;
    public static final short ASN_INDEF         =   ASN_INDEF_LTH;
    public static final short ASN_CHOICE        =   (0x100 | ASN_CONSTRUCTED);
    public static final short ASN_NONE         =    0x101;
    public static final short ASN_FUNCTION     =    0x102;
    public static final short ASN_NOTASN1      =    0x103;
    public static final short ASN_NOTYPE       =    0x104;
    
    public static final short UTCBASE = 70;
    public static final short UTCYR = 0;
    public static final short UTCYRSIZ = 2;
    public static final short UTCMO = (UTCYR + UTCYRSIZ);
    public static final short UTCMOSIZ = 2;
    public static final short UTCDA = (UTCMO + UTCMOSIZ);
    public static final short UTCDASIZ = 2;
    public static final short UTCHR = (UTCDA + UTCDASIZ);
    public static final short UTCHRSIZ = 2;
    public static final short UTCMI = (UTCHR + UTCHRSIZ);
    public static final short UTCMISIZ = 2;
    public static final short UTCSE = (UTCMI + UTCMISIZ);
    public static final short UTCSESIZ = 2;
    public static final short UTCSFXHR = 1;
    public static final short UTCSFXMI = (UTCSFXHR + UTCHRSIZ);
    public static final short UTCT_SIZE = 16;
    public static final short GENTBASE = (1900 + UTCBASE);
    public static final short GENTYR = 0;
    public static final short GENTYRSIZ = 4;
    public static final short GENTSE = (UTCSE + GENTYRSIZ - UTCYRSIZ);
    
    public static final short ASN_PLUS_INFINITY = 0x40;
    public static final short ASN_MINUS_INFINITY = 0x41;
    public static final short ISO6093NR1 = 10;
    public static final short ISO6093NR2 = 12;
    public static final short ISO6093NR3 = 14;
    
    public static final short ARRAY_SIZE = 41;
    public static final short LINE_SIZE = 80;
    
    public static final short _mos[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 
                        273, 304, 334, 365, 366};    /* last is for leap year */
                        
    public static final short typnames_typ[] = { 
         ASN_BOOLEAN,
         ASN_INTEGER,
         ASN_BITSTRING,
         ASN_OCTETSTRING,
         ASN_NULL,     
         ASN_OBJ_ID ,        
         7,                
         8,                 
         ASN_REAL,          
         ASN_ENUMERATED, 
         ASN_NUMERIC_STRING,   
         ASN_PRINTABLE_STRING, 
         ASN_T61_STRING,    
         ASN_VIDEOTEX_STRING, 
         ASN_IA5_STRING,       
         ASN_UTCTIME,         
         ASN_GENTIME,         
         ASN_GRAPHIC_STRING,  
         ASN_VISIBLE_STRING,   
         ASN_GENERAL_STRING,   
         ASN_UNIVERSAL_STRING, 
         ASN_BMP_STRING,      
         ASN_SEQUENCE,        
         ASN_SET,              
         ASN_APPL_SPEC,       
         ASN_CONT_SPEC,       
         ASN_PRIV_SPEC,    
         0,              
        };
        
        public static final String typnames_name[] = { 
            "boo",
            "int",
            "bit",
            "oct",
            "nul",
            "obj",
            "obd",
            "ext",
            "rea",
            "enu",
            "num",     
            "prt",        
            "t61",         
            "vtx",         
            "ia5",         
            "utc",        
            "gen",        
            "grs",         
            "vst",         
            "gns",         
            "unv",        
            "bmp",        
            "seq",       
            "set",         
            "app",         
            "ctx",       
            "pri",       
            "oth",    
        };
} 
