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
public class VerifyTypeDefined extends AsnChoice
    {
    public TbsAndSig hash = new TbsAndSig();
    public TbsAndSig text = new TbsAndSig();
    public TbsAndSig file = new TbsAndSig();
    public SignedAny any = new SignedAny();
    public VerifyTypeDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, hash, (short)0, (int)0x0);
        _setup(hash, text, (short)0, (int)0x0);
        _setup(text, file, (short)0, (int)0x0);
        _setup(file, any, (short)0, (int)0x0);
        }
    public VerifyTypeDefined set(VerifyTypeDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
