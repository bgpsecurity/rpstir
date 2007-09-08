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
public class SendAuditRespToBeSigned extends AsnSequence
    {
    public AsnInteger serial_num = new AsnInteger();
    public AsnGeneralizedTime date_time = new AsnGeneralizedTime();
    public Name name = new Name();
    public AuditRecs recs = new AuditRecs();
    public SendAuditRespToBeSigned()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, serial_num, (short)0, (int)0x0);
        _setup(serial_num, date_time, (short)0, (int)0x0);
        _setup(date_time, name, (short)0, (int)0x0);
        _setup(name, recs, (short)0, (int)0x0);
        }
    public SendAuditRespToBeSigned set(SendAuditRespToBeSigned frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
