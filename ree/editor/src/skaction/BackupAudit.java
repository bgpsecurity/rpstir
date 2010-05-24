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
public class BackupAudit extends AsnSequence
    {
    public NameAndKeys name = new NameAndKeys();
    public AsnInteger sk_id = new AsnInteger();
    public BackupMode to = new BackupMode();
    public BackupAudit()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)0, (int)0x0);
        _setup(name, sk_id, (short)0, (int)0x0);
        _setup(sk_id, to, (short)0, (int)0x0);
        }
    public BackupAudit set(BackupAudit frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
