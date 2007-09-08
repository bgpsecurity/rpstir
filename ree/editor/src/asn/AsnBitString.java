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

// char sfcsid[] = "@(#)AsnBitString.java 671E"
package asn;

import asn.*;

public class AsnBitString extends AsnObj
{
    public AsnBitString()
    {
        _tag = AsnStatic.ASN_BITSTRING;
        _type = (short)AsnStatic.ASN_BITSTRING;
    }

    public int read(AsnByteArray to, AsnIntRef shift)
    {
        return _readsize(to, shift, AsnStatic.ASN_READING);
    }

    public int vsize()
    {
        AsnIntRef shift = new AsnIntRef();
        AsnByteArray array = new AsnByteArray();
        return _readsize(array, shift, 0);
    }

    public int _compare(AsnBitString obj)
    {
        int lth1 = vsize();
        int lth2 = obj.vsize();
        int min = (lth1 < lth2) ? lth1 : lth2;
        AsnIntRef shift = new AsnIntRef();
        AsnByteArray arr1 = new AsnByteArray();
        AsnByteArray arr2 = new AsnByteArray();
        read(arr1, shift);
        obj.read(arr2, shift);
        int count;
        for (count = 0; (min!=0) && (arr1.index(count) ==
            arr2.index(count)); min--, count++);
        if (min!=0)
            return ((arr1.index(count) < arr2.index(count)) ? -1: 1);
        if (lth1 == lth2) return 0;
        return ((lth1 < lth2) ? -1:1);
    }

    public int write(AsnByteArray from, int lth, int shift)
    {
        short box;
        int i;
        int index = from.getPtr();
        if (from == null)
            return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        i = _check_of();
        if (i < 0) return i;
        if (_valp != null)
            _valp = null;
        byte buf[] = new byte[(int)(++lth)];
        buf[0] = (byte)shift;
        if (shift == 0)
            for (i = 1; i < lth; buf[(int)i++] = from.index(index++));
        else
        {
            box = (short)(from.index(index++));
            box <<= shift;
            buf[1] = (byte)(box & 0xFF);
            for (i=1, lth--; i<lth; )
            {
                box = (short)(from.index(index++));
                box <<= shift;
                buf[(int)i++] |= (box >>> 8);
                buf [(int)i] = (byte)(box & 0xFF);
            }
        }
        _valp = new AsnByteArray(buf, buf.length);
        _fill_upward(AsnStatic.ASN_FILLED_FLAG);
        return lth - 1;
    }

    protected int _readsize(AsnByteArray to, AsnIntRef shift, int mode)
    {
        short box;
        int i;
        int iter;
        int lth;
        int counter;
        if (to == null)
            return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        i = _check_vfilled();
        if (i <= 0)
            return _read_empty((int)i, mode);
        lth = _valp.getLength();
        if (_sub != null)
        {
            while((lth > 1) && (_valp.index(lth-1)==0))
                lth--;
            shift.val = 0;
        }
        if (mode != 0)
        {
            shift.val = _valp.index(0);
            if ((_sub != null) || (shift.val == 0))
            {
                for (iter=1, counter=0; iter<lth; to.setByte(_valp.index(iter++), counter++));
            }
            else for (iter=1, counter=0; iter<lth; iter++)
            {
              box = (short)(_valp.index(iter) << 8);
              box >>>= shift.val;
              to.setByte((byte)((to.index(counter)) | (box >>> 8)), counter++);
              to.setByte((byte)(box & 0xFF),counter);
            }
        }
        return lth - 1;
    }

}
