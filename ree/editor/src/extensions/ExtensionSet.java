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
public class ExtensionSet extends AsnOIDTableObj
    {
    public AsnObj objid[] = new AsnObj[25];
    public ExtensionSet()
        {
        int i;
	for (i = 0; i < 25; objid[i++] = new AsnObj());
        _tag = AsnStatic.ASN_OBJ_ID;
        _type = (short)AsnStatic.ASN_OBJ_ID;
        _flags |= AsnStatic.ASN_TABLE_FLAG;
        _sub = objid[0];
        _setup_table(objid[0], "2.5.29.9", objid[1]);
        _setup_table(objid[1], "2.5.29.14", objid[2]);
        _setup_table(objid[2], "2.5.29.15", objid[3]);
        _setup_table(objid[3], "2.5.29.16", objid[4]);
        _setup_table(objid[4], "2.5.29.17", objid[5]);
        _setup_table(objid[5], "2.5.29.18", objid[6]);
        _setup_table(objid[6], "2.5.29.19", objid[7]);
        _setup_table(objid[7], "2.5.29.30", objid[8]);
        _setup_table(objid[8], "2.5.29.32", objid[9]);
        _setup_table(objid[9], "2.5.29.33", objid[10]);
        _setup_table(objid[10], "2.5.29.36", objid[11]);
        _setup_table(objid[11], "2.5.29.31", objid[12]);
        _setup_table(objid[12], "2.5.29.35", objid[13]);
        _setup_table(objid[13], "2.5.29.37", objid[14]);
        _setup_table(objid[14], "2.23.42.7.1", objid[15]);
        _setup_table(objid[15], "2.23.42.7.2", objid[16]);
        _setup_table(objid[16], "2.23.42.7.3", objid[17]);
        _setup_table(objid[17], "2.23.42.7.4", objid[18]);
        _setup_table(objid[18], "2.23.42.7.5", objid[19]);
        _setup_table(objid[19], "1.3.6.1.5.5.7.1.1", objid[20]);
        _setup_table(objid[20], "1.3.6.1.5.5.7.1.11", objid[21]);
        _setup_table(objid[21], "1.3.6.1.5.5.7.1.7", objid[22]);
        _setup_table(objid[22], "1.3.6.1.5.5.7.1.8", objid[23]);
        _setup_table(objid[23], "1.3.6.1.5.5.7.1.9", objid[24]);
        _setup_table(objid[24], "0xFFFF", null);
        }
    public ExtensionSet set(ExtensionSet frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
