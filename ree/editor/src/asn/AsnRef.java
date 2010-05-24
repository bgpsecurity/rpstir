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

// char sfcsid[] = "@(#)AsnRef.java 622E"
package asn;

import asn.*;

public class AsnRef extends AsnObj
    {
    public AsnRef()
        {
        _tag = AsnStatic.ASN_ANY;
        _type = (short)AsnStatic.ASN_ANY;
        }
    public void add()
	{
	_sub = new AsnObj();
	add(_sub);
	}
    public void add(AsnObj nobj)
	{
	_sub = nobj;
	_sub._flags |= AsnStatic.ASN_DUPED_FLAG;
	_sub._supra = this;
        if ((nobj._flags & AsnStatic.ASN_FILLED_FLAG) != 0)
	    this._fill_upward(AsnStatic.ASN_FILLED_FLAG);

        }
    }

