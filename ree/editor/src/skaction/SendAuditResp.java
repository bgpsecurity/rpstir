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
public class SendAuditResp extends AsnSequence
    {
    public SendAuditRespToBeSigned toBeSigned = new SendAuditRespToBeSigned();
    public AlgorithmIdentifier algorithm = new AlgorithmIdentifier();
    public AsnBitString signature = new AsnBitString();
    public SendAuditResp()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, toBeSigned, (short)0, (int)0x0);
        _setup(toBeSigned, algorithm, (short)0, (int)0x0);
        _setup(algorithm, signature, (short)0, (int)0x0);
        }
    public SendAuditResp set(SendAuditResp frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
