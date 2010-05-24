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
public class ActivateAudit extends AsnSequence
    {
    public Name name = new Name();
    public KeyNames keyNames = new KeyNames();
    public AsnOctetString ciktags = new AsnOctetString();
    public ActivateAudit()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)0, (int)0x0);
        _setup(name, keyNames, (short)0, (int)0x0);
        _setup(keyNames, ciktags, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public ActivateAudit set(ActivateAudit frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
