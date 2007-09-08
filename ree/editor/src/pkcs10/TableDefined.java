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
public class TableDefined extends AsnChoice
    {
    public Netkey netkeyAttribute = new Netkey();
    public AsnAny unknown = new AsnAny();
    public TableDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, netkeyAttribute, (short)0, (int)0x0);
        _setup(netkeyAttribute, unknown, (short)0, (int)0x0);
        }
    public TableDefined set(TableDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
