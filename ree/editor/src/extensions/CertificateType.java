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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class CertificateType extends AsnBitString
    {
    public AsnBit card = new AsnBit();
    public AsnBit mer = new AsnBit();
    public AsnBit pgwy = new AsnBit();
    public AsnBit cca = new AsnBit();
    public AsnBit mca = new AsnBit();
    public AsnBit pca = new AsnBit();
    public AsnBit gca = new AsnBit();
    public AsnBit bca = new AsnBit();
    public AsnBit rca = new AsnBit();
    public AsnBit acq = new AsnBit();
    public CertificateType()
        {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
        _set_tag(card, (int)0);
        _setup((AsnObj)null, card, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(mer, (int)1);
        _setup(card, mer, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(pgwy, (int)2);
        _setup(mer, pgwy, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(cca, (int)3);
        _setup(pgwy, cca, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(mca, (int)4);
        _setup(cca, mca, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(pca, (int)5);
        _setup(mca, pca, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(gca, (int)6);
        _setup(pca, gca, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(bca, (int)7);
        _setup(gca, bca, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(rca, (int)8);
        _setup(bca, rca, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(acq, (int)9);
        _setup(rca, acq, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public CertificateType set(CertificateType frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
