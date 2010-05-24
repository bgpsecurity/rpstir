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
public class Other_name extends AsnArray
    {
    public Other_nameTableInOther_name type_id = new Other_nameTableInOther_name();
    public Other_nameTableDefined value = new Other_nameTableDefined();
    public Other_name()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, type_id, (short)0, (int)0x0);
        _setup(type_id, value, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        Other_name objp = new Other_name();
        _set_pointers(objp);
        return objp;
        }

    public Other_name index(int index)
        {
        return (Other_name)_index_op(index);
        }

    public Other_name set(Other_name frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
