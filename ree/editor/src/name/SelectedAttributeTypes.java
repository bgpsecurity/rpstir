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
package name;
import asn.*;
public class SelectedAttributeTypes extends AsnOIDTableObj
    {
    public AsnObj objid[] = new AsnObj[29];
    public SelectedAttributeTypes()
        {
        int i;
	for (i = 0; i < 29; objid[i++] = new AsnObj());
        _tag = AsnStatic.ASN_OBJ_ID;
        _type = (short)AsnStatic.ASN_OBJ_ID;
        _flags |= AsnStatic.ASN_TABLE_FLAG;
        _sub = objid[0];
        _setup_table(objid[0], "2.5.4.3", objid[1]);
        _setup_table(objid[1], "2.5.4.4", objid[2]);
        _setup_table(objid[2], "2.5.4.5", objid[3]);
        _setup_table(objid[3], "2.5.4.6", objid[4]);
        _setup_table(objid[4], "2.5.4.7", objid[5]);
        _setup_table(objid[5], "2.5.4.8", objid[6]);
        _setup_table(objid[6], "2.5.4.9", objid[7]);
        _setup_table(objid[7], "2.5.4.10", objid[8]);
        _setup_table(objid[8], "2.5.4.11", objid[9]);
        _setup_table(objid[9], "2.5.4.12", objid[10]);
        _setup_table(objid[10], "2.5.4.13", objid[11]);
        _setup_table(objid[11], "2.5.4.15", objid[12]);
        _setup_table(objid[12], "2.5.4.17", objid[13]);
        _setup_table(objid[13], "2.5.4.18", objid[14]);
        _setup_table(objid[14], "2.5.4.19", objid[15]);
        _setup_table(objid[15], "2.5.4.20", objid[16]);
        _setup_table(objid[16], "2.5.4.24", objid[17]);
        _setup_table(objid[17], "2.5.4.25", objid[18]);
        _setup_table(objid[18], "2.5.4.27", objid[19]);
        _setup_table(objid[19], "2.5.4.35", objid[20]);
        _setup_table(objid[20], "2.5.4.41", objid[21]);
        _setup_table(objid[21], "2.5.4.42", objid[22]);
        _setup_table(objid[22], "2.5.4.44", objid[23]);
        _setup_table(objid[23], "2.5.4.43", objid[24]);
        _setup_table(objid[24], "1.3.6.1.4.1.42.2.11.2.1", objid[25]);
        _setup_table(objid[25], "2.5.4.45", objid[26]);
        _setup_table(objid[26], "1.2.840.113549.1.9.1", objid[27]);
        _setup_table(objid[27], "0.9.2342.19200300.100.1.25", objid[28]);
        _setup_table(objid[28], "0xFFFF", null);
        }
    public SelectedAttributeTypes set(SelectedAttributeTypes frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
