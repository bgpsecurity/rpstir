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
public class RuleType extends AsnInteger
    {
    public AsnObj pub_key = new AsnObj();
    public AsnObj ra_cert = new AsnObj();
    public AsnObj crl = new AsnObj();
    public AsnObj cert = new AsnObj();
    public AsnObj alt1 = new AsnObj();
    public AsnObj alt2 = new AsnObj();
    public AsnObj alt3 = new AsnObj();
    public RuleType()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(pub_key, (int)1);
        _setup((AsnObj)null, pub_key, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(ra_cert, (int)2);
        _setup(pub_key, ra_cert, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(crl, (int)3);
        _setup(ra_cert, crl, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(cert, (int)4);
        _setup(crl, cert, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(alt1, (int)5);
        _setup(cert, alt1, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(alt2, (int)6);
        _setup(alt1, alt2, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(alt3, (int)7);
        _setup(alt2, alt3, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public RuleType set(RuleType frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
