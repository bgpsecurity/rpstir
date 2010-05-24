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
public class RunDiagsReq extends AsnBitString
    {
    public AsnBit ram = new AsnBit();
    public AsnBit bbram = new AsnBit();
    public AsnBit eeprom = new AsnBit();
    public AsnBit flash = new AsnBit();
    public AsnBit prom = new AsnBit();
    public AsnBit algs = new AsnBit();
    public AsnBit rng = new AsnBit();
    public AsnBit battery = new AsnBit();
    public AsnBit bus_err = new AsnBit();
    public AsnBit addr_err = new AsnBit();
    public RunDiagsReq()
        {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
        _set_tag(ram, (int)1);
        _setup((AsnObj)null, ram, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(bbram, (int)2);
        _setup(ram, bbram, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(eeprom, (int)3);
        _setup(bbram, eeprom, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(flash, (int)4);
        _setup(eeprom, flash, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(prom, (int)5);
        _setup(flash, prom, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(algs, (int)6);
        _setup(prom, algs, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(rng, (int)7);
        _setup(algs, rng, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(battery, (int)8);
        _setup(rng, battery, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(bus_err, (int)9);
        _setup(battery, bus_err, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(addr_err, (int)10);
        _setup(bus_err, addr_err, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public RunDiagsReq set(RunDiagsReq frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
