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
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class NewKeyResp extends AsnSequence
    {
    public AsnOctetString keyName = new AsnOctetString();
    public NewKeySigned ca_resp = new NewKeySigned();
//    public CertificationRequest pkcs10 = new CertificationRequest();
    public NewKeyResp()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, keyName, (short)0, (int)0x0);
        keyName._boundset(1, 16);
        _setup(keyName, ca_resp, (short)0, (int)0x0);
//        _setup(ca_resp, pkcs10, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public NewKeyResp set(NewKeyResp frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
