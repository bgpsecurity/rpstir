/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
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
package pkcs10;
import certificate.*;
import name.*;
import Algorithms.*;
import asn.*;
public class Table extends AsnOIDTableObj
    {
    public AsnObj objid[] = new AsnObj[2];
    public Table()
        {
        int i;
	for (i = 0; i < 2; objid[i++] = new AsnObj());
        _tag = AsnStatic.ASN_OBJ_ID;
        _type = (short)AsnStatic.ASN_OBJ_ID;
        _flags |= AsnStatic.ASN_TABLE_FLAG;
        _sub = objid[0];
        _setup_table(objid[0], "2.16.840.101.3.3.1.8.1", objid[1]);
        _setup_table(objid[1], "0xFFFF", null);
        }
    public Table set(Table frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
