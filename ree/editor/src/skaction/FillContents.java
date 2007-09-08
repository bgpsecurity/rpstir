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
public class FillContents extends AsnChoice
    {
    public Name backup = new Name();
    public FillPublicKey publicKey = new FillPublicKey();
    public SignedRulePackage rulePkg = new SignedRulePackage();
    public AsnOctetString other = new AsnOctetString();
    public FillContents()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, backup, (short)0, (int)0xA1);
        _setup(backup, publicKey, (short)0, (int)0xA2);
        _setup(publicKey, rulePkg, (short)0, (int)0xA3);
        _setup(rulePkg, other, (short)0, (int)0x84);
        }
    public FillContents set(FillContents frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
