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

// char sfcsid[] = "@(#)AsnInteger.java 622E"
package asn;

import asn.*;

public class AsnInteger extends AsnNumeric
{
    protected int _default;

    public AsnInteger()
    {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _default = 0;
    }

    public void _set_def(int value)
    {
        _default = value;
    }

    public int _get_def()
    {
        return _default;
    }

    public void set(int val)
    {
        write(val);
    }

    public int _num_diff(AsnByteArray value, int lth)
    {
        //compares 2 integers
        int count;
        byte ch = 0;
        if ((_valp.index(0) & 0x80) != (value.index(0) & 0x80))
        {
            if ((_valp.index(0) & 0x80) != 0) return -1;
            else return 1;
        }
        int begin = 0;
        int end = value.getLength();
        for (count = 0; (begin < end) && (value.index(begin) ==
            (ch = _valp.index(count))); begin++, count++);
        if (_valp.getLength() < lth) count = -1;
        else if (_valp.getLength() > lth) count = 1;
        else if (begin >= end) count = 0;
        else if (ch < value.index(begin)) count = -1;
        else count = 1;

        if ((value.index(0) & 0x80) != 0) return -count;
        return count;
    }

}
