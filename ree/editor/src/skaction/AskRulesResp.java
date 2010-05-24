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
public class AskRulesResp extends AsnSequence
    {
    public Name ca = new Name();
    public AsnOctetString keyName = new AsnOctetString();
    public NoncedRuleSets rules = new NoncedRuleSets();
    public AskRulesResp()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, ca, (short)0, (int)0x0);
        _setup(ca, keyName, (short)0, (int)0x0);
        keyName._boundset(1, 16);
        _setup(keyName, rules, (short)0, (int)0x0);
        }
    public AskRulesResp set(AskRulesResp frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
