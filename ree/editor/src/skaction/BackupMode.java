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
public class BackupMode extends AsnBitString
    {
    public AsnBit fill = new AsnBit();
    public AsnBit ws = new AsnBit();
    public BackupMode()
        {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
        _set_tag(fill, (int)0);
        _setup((AsnObj)null, fill, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(ws, (int)1);
        _setup(fill, ws, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public BackupMode set(BackupMode frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
