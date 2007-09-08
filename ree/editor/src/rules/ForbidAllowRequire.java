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
package rules;
import name.*;
import asn.*;
public class ForbidAllowRequire extends AsnChoice
    {
    public Targets forbid = new Targets();
    public Targets allow = new Targets();
    public Targets require = new Targets();
    public Targets part_forbid = new Targets();
    public Targets part_allow = new Targets();
    public ForbidAllowRequire()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, forbid, (short)0, (int)0xA0);
        _setup(forbid, allow, (short)0, (int)0xA1);
        _setup(allow, require, (short)0, (int)0xA2);
        _setup(require, part_forbid, (short)0, (int)0xA3);
        _setup(part_forbid, part_allow, (short)0, (int)0xA4);
        }
    public ForbidAllowRequire set(ForbidAllowRequire frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
