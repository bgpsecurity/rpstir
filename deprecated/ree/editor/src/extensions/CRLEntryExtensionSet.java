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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class CRLEntryExtensionSet extends AsnOIDTableObj
    {
    public AsnObj objid[] = new AsnObj[5];
    public CRLEntryExtensionSet()
        {
        int i;
	for (i = 0; i < 5; objid[i++] = new AsnObj());
        _tag = AsnStatic.ASN_OBJ_ID;
        _type = (short)AsnStatic.ASN_OBJ_ID;
        _flags |= AsnStatic.ASN_TABLE_FLAG;
        _sub = objid[0];
        _setup_table(objid[0], "2.5.29.21", objid[1]);
        _setup_table(objid[1], "2.5.29.24", objid[2]);
        _setup_table(objid[2], "2.5.29.23", objid[3]);
        _setup_table(objid[3], "2.5.29.29", objid[4]);
        _setup_table(objid[4], "0xFFFF", null);
        }
    public CRLEntryExtensionSet set(CRLEntryExtensionSet frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
