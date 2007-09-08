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
public class ConfigFlags extends AsnBitString
    {
    public AsnBit keep_auth = new AsnBit();
    public AsnBit ia_com = new AsnBit();
    public AsnBit subj_com = new AsnBit();
    public AsnBit reuse_sk = new AsnBit();
    public AsnBit chk_subj = new AsnBit();
    public AsnBit iasc_eepr = new AsnBit();
    public AsnBit iasc_ws = new AsnBit();
    public AsnBit anyname = new AsnBit();
    public AsnBit top_level = new AsnBit();
    public AsnBit ctrl_auth = new AsnBit();
    public AsnBit sign_any = new AsnBit();
    public AsnBit any_ia = new AsnBit();
    public AsnBit ia_kids = new AsnBit();
    public AsnBit sign_hash = new AsnBit();
    public AsnBit crypto_officer = new AsnBit();
    public AsnBit fermat_0 = new AsnBit();
    public AsnBit fips_140 = new AsnBit();
    public ConfigFlags()
        {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
        _set_tag(keep_auth, (int)1);
        _setup((AsnObj)null, keep_auth, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(ia_com, (int)2);
        _setup(keep_auth, ia_com, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(subj_com, (int)3);
        _setup(ia_com, subj_com, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(reuse_sk, (int)4);
        _setup(subj_com, reuse_sk, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(chk_subj, (int)5);
        _setup(reuse_sk, chk_subj, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(iasc_eepr, (int)6);
        _setup(chk_subj, iasc_eepr, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(iasc_ws, (int)7);
        _setup(iasc_eepr, iasc_ws, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(anyname, (int)8);
        _setup(iasc_ws, anyname, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(top_level, (int)9);
        _setup(anyname, top_level, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(ctrl_auth, (int)10);
        _setup(top_level, ctrl_auth, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_any, (int)11);
        _setup(ctrl_auth, sign_any, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(any_ia, (int)12);
        _setup(sign_any, any_ia, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(ia_kids, (int)13);
        _setup(any_ia, ia_kids, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(sign_hash, (int)14);
        _setup(ia_kids, sign_hash, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(crypto_officer, (int)15);
        _setup(sign_hash, crypto_officer, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(fermat_0, (int)16);
        _setup(crypto_officer, fermat_0, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(fips_140, (int)17);
        _setup(fermat_0, fips_140, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public ConfigFlags set(ConfigFlags frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
