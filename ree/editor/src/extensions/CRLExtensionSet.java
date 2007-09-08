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
public class CRLExtensionSet extends AsnOIDTableObj
    {
    public AsnObj objid[] = new AsnObj[6];
    public CRLExtensionSet()
        {
        int i;
	for (i = 0; i < 6; objid[i++] = new AsnObj());
        _tag = AsnStatic.ASN_OBJ_ID;
        _type = (short)AsnStatic.ASN_OBJ_ID;
        _flags |= AsnStatic.ASN_TABLE_FLAG;
        _sub = objid[0];
        _setup_table(objid[0], "2.5.29.35", objid[1]);
        _setup_table(objid[1], "2.5.29.18", objid[2]);
        _setup_table(objid[2], "2.5.29.20", objid[3]);
        _setup_table(objid[3], "2.5.29.28", objid[4]);
        _setup_table(objid[4], "2.5.29.27", objid[5]);
        _setup_table(objid[5], "0xFFFF", null);
        }
    public CRLExtensionSet set(CRLExtensionSet frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
