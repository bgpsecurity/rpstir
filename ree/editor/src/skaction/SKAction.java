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
public class SKAction extends AsnChoice
    {
    public SKRequest req = new SKRequest();
    public SKResponse resp = new SKResponse();
    public ErrorResp err = new ErrorResp();
    public SKAction()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, req, (short)0, (int)0xA0);
        _setup(req, resp, (short)0, (int)0xA1);
        _setup(resp, err, (short)0, (int)0xA3);
        }
    public SKAction set(SKAction frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
