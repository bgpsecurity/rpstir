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
public class AskResp extends AsnSequence
    {
    public Name name = new Name();
    public SKConfig config = new SKConfig();
    public AsnOctetString cik_tag = new AsnOctetString();
    public FillContents fill = new FillContents();
    public CAConfigs caConfigs = new CAConfigs();
    public AskResp()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)0, (int)0x0);
        _setup(name, config, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA0);
        _setup(config, cik_tag, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        cik_tag._boundset(8, 8);
        _setup(cik_tag, fill, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(fill, caConfigs, (short)0, (int)0x0);
        }
    public AskResp set(AskResp frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
