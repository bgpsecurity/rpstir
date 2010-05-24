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
public class ErrorTableDefined extends AsnChoice
    {
    public AsnInteger bad_asn1 = new AsnInteger();
    public AsnUTF8String bad_knam = new AsnUTF8String();
    public FailRuleResp bad_rule = new FailRuleResp();
    public FailRuleResp fail_rule = new FailRuleResp();
    public AsnNone other = new AsnNone();
    public ErrorTableDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, bad_asn1, (short)0, (int)0x0);
        _setup(bad_asn1, bad_knam, (short)0, (int)0x0);
        _setup(bad_knam, bad_rule, (short)0, (int)0x0);
        _setup(bad_rule, fail_rule, (short)0, (int)0x0);
        _setup(fail_rule, other, (short)0, (int)0x0);
        }
    public ErrorTableDefined set(ErrorTableDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
