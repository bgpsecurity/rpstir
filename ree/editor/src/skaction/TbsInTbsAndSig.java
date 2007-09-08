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
public class TbsInTbsAndSig extends AsnChoice
    {
    public AsnOctetString hash = new AsnOctetString();
    public AsnTeletexString text = new AsnTeletexString();
    public AsnInteger length = new AsnInteger();
    public TbsInTbsAndSig()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, hash, (short)0, (int)0x0);
        _setup(hash, text, (short)0, (int)0x0);
        _setup(text, length, (short)0, (int)0x0);
        }
    public TbsInTbsAndSig set(TbsInTbsAndSig frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
