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
package rules;
import name.*;
import asn.*;
public class Location extends AsnArray
    {
    public AsnPrintableString path = new AsnPrintableString();
    public AsnInteger tagtype = new AsnInteger();
    public FindID id = new FindID();
    public Location()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, path, (short)0, (int)0x0);
        _setup(path, tagtype, (short)0, (int)0x80);
        _setup(tagtype, id, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        Location objp = new Location();
        _set_pointers(objp);
        return objp;
        }

    public Location index(int index)
        {
        return (Location)_index_op(index);
        }

    public Location set(Location frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
