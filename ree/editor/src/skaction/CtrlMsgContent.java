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
public class CtrlMsgContent extends AsnChoice
    {
    public SKConfig cnfg_sk = new SKConfig();
    public CAConfig cnfg_ca = new CAConfig();
    public NameAndKeys canc_ca = new NameAndKeys();
    public CAConfig canc_resp = new CAConfig();
    public AsnBitString rdy_load = new AsnBitString();
    public CtrlMsgContent()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, cnfg_sk, (short)0, (int)0xA1);
        _setup(cnfg_sk, cnfg_ca, (short)0, (int)0xA2);
        _setup(cnfg_ca, canc_ca, (short)0, (int)0xA4);
        _setup(canc_ca, canc_resp, (short)0, (int)0xA5);
        _setup(canc_resp, rdy_load, (short)0, (int)0x0);
        }
    public CtrlMsgContent set(CtrlMsgContent frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
