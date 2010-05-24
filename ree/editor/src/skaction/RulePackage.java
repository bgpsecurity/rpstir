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
public class RulePackage extends AsnSequence
    {
    public Name ca = new Name();
    public AsnOctetString keyName = new AsnOctetString();
    public AsnGeneralizedTime nonce = new AsnGeneralizedTime();
    public RuleSets ruleSets = new RuleSets();
    public RulePackage()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, ca, (short)0, (int)0x0);
        _setup(ca, keyName, (short)0, (int)0x0);
        keyName._boundset(1, 16);
        _setup(keyName, nonce, (short)0, (int)0x0);
        _setup(nonce, ruleSets, (short)0, (int)0x0);
        }
    public RulePackage set(RulePackage frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
