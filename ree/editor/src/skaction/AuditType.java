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
public class AuditType extends AsnNumTableObj
    {
    public AsnObj objid[] = new AsnObj[8];
    public AuditType()
        {
        int i;
	for (i = 0; i < 8; objid[i++] = new AsnObj());
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _flags |= AsnStatic.ASN_TABLE_FLAG;
        _sub = objid[0];
        _setup_table(objid[0], "2", objid[1]);
        _setup_table(objid[1], "6", objid[2]);
        _setup_table(objid[2], "10", objid[3]);
        _setup_table(objid[3], "74", objid[4]);
        _setup_table(objid[4], "8", objid[5]);
        _setup_table(objid[5], "22", objid[6]);
        _setup_table(objid[6], "36", objid[7]);
        _setup_table(objid[7], "44", null);
        }
    public AuditType set(AuditType frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
