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
public class SKReqTable extends AsnNumTableObj
    {
    public AsnObj objid[] = new AsnObj[25];
    public SKReqTable()
        {
        int i;
	for (i = 0; i < 25; objid[i++] = new AsnObj());
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _flags |= AsnStatic.ASN_TABLE_FLAG;
        _sub = objid[0];
        _setup_table(objid[0], "2", objid[1]);
        _setup_table(objid[1], "4", objid[2]);
        _setup_table(objid[2], "6", objid[3]);
        _setup_table(objid[3], "8", objid[4]);
        _setup_table(objid[4], "10", objid[5]);
        _setup_table(objid[5], "12", objid[6]);
        _setup_table(objid[6], "14", objid[7]);
        _setup_table(objid[7], "20", objid[8]);
        _setup_table(objid[8], "22", objid[9]);
        _setup_table(objid[9], "36", objid[10]);
        _setup_table(objid[10], "44", objid[11]);
        _setup_table(objid[11], "46", objid[12]);
        _setup_table(objid[12], "48", objid[13]);
        _setup_table(objid[13], "50", objid[14]);
        _setup_table(objid[14], "64", objid[15]);
        _setup_table(objid[15], "74", objid[16]);
        _setup_table(objid[16], "84", objid[17]);
        _setup_table(objid[17], "86", objid[18]);
        _setup_table(objid[18], "90", objid[19]);
        _setup_table(objid[19], "98", objid[20]);
        _setup_table(objid[20], "94", objid[21]);
        _setup_table(objid[21], "96", objid[22]);
        _setup_table(objid[22], "100", objid[23]);
        _setup_table(objid[23], "102", objid[24]);
        _setup_table(objid[24], "104", null);
        }
    public SKReqTable set(SKReqTable frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
