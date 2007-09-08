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
package Algorithms;
import asn.*;
public class AlgorithmTable extends AsnOIDTableObj
    {
    public AsnObj objid[] = new AsnObj[52];
    public AlgorithmTable()
        {
        int i;
	for (i = 0; i < 52; objid[i++] = new AsnObj());
        _tag = AsnStatic.ASN_OBJ_ID;
        _type = (short)AsnStatic.ASN_OBJ_ID;
        _flags |= AsnStatic.ASN_TABLE_FLAG;
        _sub = objid[0];
        _setup_table(objid[0], "2.16.840.1.101.2.1.1.1", objid[1]);
        _setup_table(objid[1], "2.16.840.1.101.2.1.1.2", objid[2]);
        _setup_table(objid[2], "2.16.840.1.101.2.1.1.3", objid[3]);
        _setup_table(objid[3], "2.16.840.1.101.2.1.1.4", objid[4]);
        _setup_table(objid[4], "2.16.840.1.101.2.1.1.5", objid[5]);
        _setup_table(objid[5], "2.16.840.1.101.2.1.1.6", objid[6]);
        _setup_table(objid[6], "2.16.840.1.101.2.1.1.7", objid[7]);
        _setup_table(objid[7], "2.16.840.1.101.2.1.1.8", objid[8]);
        _setup_table(objid[8], "2.16.840.1.101.2.1.1.9", objid[9]);
        _setup_table(objid[9], "2.16.840.1.101.2.1.1.10", objid[10]);
        _setup_table(objid[10], "2.16.840.1.101.2.1.1.11", objid[11]);
        _setup_table(objid[11], "2.16.840.1.101.2.1.1.12", objid[12]);
        _setup_table(objid[12], "1.3.14.3.2.2", objid[13]);
        _setup_table(objid[13], "1.3.14.3.2.3", objid[14]);
        _setup_table(objid[14], "1.3.14.3.2.4", objid[15]);
        _setup_table(objid[15], "1.3.14.3.2.6", objid[16]);
        _setup_table(objid[16], "1.3.14.3.2.7", objid[17]);
        _setup_table(objid[17], "1.3.14.3.2.8", objid[18]);
        _setup_table(objid[18], "1.3.14.3.2.9", objid[19]);
        _setup_table(objid[19], "1.3.14.3.2.10", objid[20]);
        _setup_table(objid[20], "1.3.14.3.2.11", objid[21]);
        _setup_table(objid[21], "1.3.14.3.2.12", objid[22]);
        _setup_table(objid[22], "1.3.14.3.2.13", objid[23]);
        _setup_table(objid[23], "1.3.14.3.2.27", objid[24]);
        _setup_table(objid[24], "1.3.14.3.2.14", objid[25]);
        _setup_table(objid[25], "1.3.14.3.2.15", objid[26]);
        _setup_table(objid[26], "1.3.14.3.2.29", objid[27]);
        _setup_table(objid[27], "1.3.14.3.2.16", objid[28]);
        _setup_table(objid[28], "1.3.14.3.2.17", objid[29]);
        _setup_table(objid[29], "1.3.14.3.2.18", objid[30]);
        _setup_table(objid[30], "1.3.14.3.2.19", objid[31]);
        _setup_table(objid[31], "1.3.14.3.2.20", objid[32]);
        _setup_table(objid[32], "1.3.14.3.2.21", objid[33]);
        _setup_table(objid[33], "1.3.14.3.2.22", objid[34]);
        _setup_table(objid[34], "1.3.14.3.2.23", objid[35]);
        _setup_table(objid[35], "1.2.840.113549.2.2", objid[36]);
        _setup_table(objid[36], "1.2.840.113549.2.4", objid[37]);
        _setup_table(objid[37], "1.2.840.113549.2.5", objid[38]);
        _setup_table(objid[38], "1.2.840.113549.1.1.2", objid[39]);
        _setup_table(objid[39], "1.2.840.113549.1.1.4", objid[40]);
        _setup_table(objid[40], "1.2.840.113549.1.1.5", objid[41]);
        _setup_table(objid[41], "1.2.840.113549.1.1.1", objid[42]);
        _setup_table(objid[42], "1.2.840.113549.1.3.1", objid[43]);
        _setup_table(objid[43], "1.2.840.113549.3.2", objid[44]);
        _setup_table(objid[44], "1.2.840.113549.3.4", objid[45]);
        _setup_table(objid[45], "1.3.14.7.2.1.1", objid[46]);
        _setup_table(objid[46], "1.3.14.7.2.3.1", objid[47]);
        _setup_table(objid[47], "1.3.14.7.2.3.2", objid[48]);
        _setup_table(objid[48], "1.2.840.10040.4.1", objid[49]);
        _setup_table(objid[49], "1.2.840.10040.4.3", objid[50]);
        _setup_table(objid[50], "1.2.840.113549.1.1.11", objid[51]);
        _setup_table(objid[51], "0xFFFF", null);
        }
    public AlgorithmTable set(AlgorithmTable frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
