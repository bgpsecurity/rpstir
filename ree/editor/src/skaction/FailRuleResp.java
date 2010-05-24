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
public class FailRuleResp extends AsnSequence
    {
    public AsnInteger offset_in_object = new AsnInteger();
    public AsnUTF8String rule_file_name = new AsnUTF8String();
    public AsnInteger offset_in_rule = new AsnInteger();
    public AsnUTF8String rule_name = new AsnUTF8String();
    public FailRuleResp()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, offset_in_object, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(offset_in_object, rule_file_name, (short)0, (int)0x0);
        _setup(rule_file_name, offset_in_rule, (short)0, (int)0x0);
        _setup(offset_in_rule, rule_name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public FailRuleResp set(FailRuleResp frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
