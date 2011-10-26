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
public class KeyUses extends AsnBitString
    {
    public AsnBit encrypt = new AsnBit();
    public AsnBit sign_ctf = new AsnBit();
    public AsnBit sign_crl = new AsnBit();
    public AsnBit sign_text = new AsnBit();
    public AsnBit sign_any = new AsnBit();
    public AsnBit sign_hash = new AsnBit();
    public AsnBit sign_ctrl = new AsnBit();
    public AsnBit sign_file = new AsnBit();
    public AsnBit key_gen = new AsnBit();
    public AsnBit key_arch = new AsnBit();
    public AsnBit key_recov = new AsnBit();
    public AsnBit sign_rules = new AsnBit();
    public KeyUses()
        {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
        _set_tag(encrypt, (int)0);
        _setup((AsnObj)null, encrypt, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_ctf, (int)1);
        _setup(encrypt, sign_ctf, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_crl, (int)2);
        _setup(sign_ctf, sign_crl, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_text, (int)3);
        _setup(sign_crl, sign_text, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_any, (int)4);
        _setup(sign_text, sign_any, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_hash, (int)5);
        _setup(sign_any, sign_hash, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_ctrl, (int)6);
        _setup(sign_hash, sign_ctrl, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_file, (int)7);
        _setup(sign_ctrl, sign_file, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(key_gen, (int)8);
        _setup(sign_file, key_gen, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(key_arch, (int)9);
        _setup(key_gen, key_arch, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(key_recov, (int)10);
        _setup(key_arch, key_recov, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_rules, (int)11);
        _setup(key_recov, sign_rules, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public KeyUses set(KeyUses frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
