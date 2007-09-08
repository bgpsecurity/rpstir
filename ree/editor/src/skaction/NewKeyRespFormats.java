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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class NewKeyRespFormats extends AsnBitString
    {
    public AsnBit pkcs10 = new AsnBit();
    public NewKeyRespFormats()
        {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
        _set_tag(pkcs10, (int)0);
        _setup((AsnObj)null, pkcs10, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public NewKeyRespFormats set(NewKeyRespFormats frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
