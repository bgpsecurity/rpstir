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
public class SKConfig extends AsnSequence
    {
    public ConfigFlags flags_on = new ConfigFlags();
    public ConfigFlags flags_off = new ConfigFlags();
    public AsnInteger copy_cik_secs = new AsnInteger();
    public AsnInteger cert_valid_mos = new AsnInteger();
    public AsnInteger next_crl_mos = new AsnInteger();
    public SubjectPublicKeyInfo spec_pub_key = new SubjectPublicKeyInfo();
    public SubjectPublicKeyInfo ctrl_pub_key = new SubjectPublicKeyInfo();
    public AsnInteger max_ctf_vers = new AsnInteger();
    public AsnOctetString release = new AsnOctetString();
    public AsnInteger free_eeprom = new AsnInteger();
    public AsnGeneralizedTime date_time = new AsnGeneralizedTime();
    public AsnInteger audit_size = new AsnInteger();
    public AsnInteger last_audit_num = new AsnInteger();
    public AsnBitString co_processors = new AsnBitString();
    public AsnInteger rsa_def_key = new AsnInteger();
    public AsnInteger rsa_min_key = new AsnInteger();
    public AsnInteger rsa_max_key = new AsnInteger();
    public AsnInteger dsa_def_key = new AsnInteger();
    public AsnInteger dsa_min_key = new AsnInteger();
    public AsnInteger dsa_max_key = new AsnInteger();
    public SKConfig()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, flags_on, (short)0, (int)0x0);
        _setup(flags_on, flags_off, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(flags_off, copy_cik_secs, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x80);
        _setup(copy_cik_secs, cert_valid_mos, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        _setup(cert_valid_mos, next_crl_mos, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x82);
        _setup(next_crl_mos, spec_pub_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA3);
        _setup(spec_pub_key, ctrl_pub_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA4);
        _setup(ctrl_pub_key, max_ctf_vers, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x85);
        _setup(max_ctf_vers, release, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x86);
        _setup(release, free_eeprom, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x87);
        _setup(free_eeprom, date_time, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x88);
        _setup(date_time, audit_size, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x89);
        _setup(audit_size, last_audit_num, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x8A);
        _setup(last_audit_num, co_processors, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x8B);
        _setup(co_processors, rsa_def_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x90);
        _setup(rsa_def_key, rsa_min_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x91);
        _setup(rsa_min_key, rsa_max_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x92);
        _setup(rsa_max_key, dsa_def_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x93);
        _setup(dsa_def_key, dsa_min_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x94);
        _setup(dsa_min_key, dsa_max_key, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x95);
        }
    public SKConfig set(SKConfig frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
