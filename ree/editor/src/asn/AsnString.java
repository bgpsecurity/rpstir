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

// char sfcsid[] = "@(#)AsnString.java 622E"
package asn;

import asn.*;

public class AsnString extends AsnObj
{
    public AsnString()
    {
        //empty function
    }

    public boolean equals(AsnByteArray in)
    {
        AsnByteArray array;
        if (_type != AsnStatic.ASN_OBJ_ID)
            return _valp.equals(in);
        int ansr = ((AsnObj)this).vsize();
        if (ansr != (in.getLength() + 1))
            return false;
        array = new AsnByteArray();
        ((AsnObj)this).read(array);
        int retval = in.compare(array, (int)ansr);
        return (retval == 0);
    }

    public int _compare(AsnString asnString)
    {
        int ansr;
        int lth1 = _valp.getLength();
        int lth2 = asnString._valp.getLength();
        int min = (lth1 < lth2) ? lth1 : lth2;
        for (ansr=0; (ansr<min) && (_valp.index(ansr)
            == asnString._valp.index(ansr)); ansr++);
        if (ansr >= min)
        {
            if (lth1==lth2) return 0;
            if (lth1 > min) return 1;
            return -1;
        }
        if (_valp.index(ansr) < asnString._valp.index(ansr)) return -1;
        return 1;
    }
}
