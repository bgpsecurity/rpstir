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

// char sfcsid[] = "@(#)AsnOIDTableObj.java 663E"
package asn;

import asn.*;

public class AsnOIDTableObj extends AsnTableObj
{
    public AsnOIDTableObj()
    {
        //an empty function
    }

    public int write(String from)
        {
	AsnByteArray ba = new AsnByteArray();
	int lth;

        if (from == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
	_clear_error();
	lth = _convertDotNotation(ba, from);
	if (lth < 0) return lth;
	return _write(ba, lth);
        }

    public boolean equals(AsnByteArray buffer)
    {
        int ansr = ((AsnObj)this).vsize();
        if (ansr != (buffer.getLength() + 1))
            return false;
        AsnByteArray array = new AsnByteArray();
        ((AsnObj)this).read(array);
        int retval = buffer.compare(array, (int)ansr - 1);
        return (retval == 0);
    }

    public boolean greaterThanOrEquals(AsnOIDTableObj obj)
    {
        return (_compare(obj) >= 0);
    }

    public boolean lessThanOrEquals(AsnOIDTableObj obj)
    {
        return (_compare(obj) <= 0);
    }

    public boolean greaterThan(AsnOIDTableObj obj)
    {
        return (_compare(obj) > 0);
    }

    public boolean lessThan(AsnOIDTableObj obj)
    {
        return (_compare(obj) < 0);
    }

    public int _compare(AsnOIDTableObj obj)
    {
        int ansr;
        int lth1 = _valp.getLength();
        int lth2 = obj._valp.getLength();
        int min = (lth1 < lth2) ? lth1 : lth2;
        for (ansr = 0;(ansr < min) && (_valp.index(ansr) == obj._valp.index(ansr));ansr++);
        if (ansr >= min)
        {
            if (lth1 == lth2) return 0;
            if (lth1 > min) return 1;
            return -1;
        }
        if (_valp.index(ansr) < obj._valp.index(ansr)) return -1;
        return 1;
    }

    public int write(AsnByteArray from)
        {
	int ansr = write(from, from.getLength());
	return ansr;
        }

    public int write(AsnByteArray from, int lth)
    {
        /**Procedure:
        1. Form first field
           Find out how much space that requires
        2. Find out how much space the remaining fields need
        3. Convert the dot notation to binary
           Call _write to do the table stuff etc.**/
        int begin = from.getPtr(), end = (int)lth;
        AsnObj obj = this;

        /* Step 1 */
        if (from == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        while ((begin < end) && (((from.index(begin)>='0') && (from.index(begin)<='9'))
            || (from.index(begin) == '.'))) begin++;
        if ((begin < from.getLength()) && (from.index(begin)!=0) && (begin < end))
            return (begin - from.getPtr()) + 1 + asn_obj_err(AsnStatic.ASN_MASK_ERR);

        int val = 0;
        for (begin = from.getPtr(); (begin < end) && (from.index(begin)!=0) &&
            (from.index(begin)!='.'); val = (val*10) + from.index(begin++) - '0');
        val *= 40;
        int temp = 0;
        for (begin++; (begin < end) && (from.index(begin)!=0) &&
            (from.index(begin)!='.'); temp = (temp*10) + from.index(begin++) - '0');
        temp += val;
        int siz = 0;
        for (val = temp; temp != 0; siz++) temp >>=7;
        /* Step 2 */
        for (begin++; (begin < end) && (from.index(begin)!=0); begin++)
        {
            for (temp = 0; (begin < end) && (from.index(begin)!=0) &&
                (from.index(begin)!='.'); temp = (temp*10) + from.index(begin++) - '0');
            if (temp == 0) siz ++;
            else for ( ; temp!=0; siz++) temp >>= 7;
        }

        for (begin = from.getPtr(); (begin < end) && (from.index(begin)!=0) &&
            (from.index(begin)!='.'); begin++);
        for (begin++; (begin < end) && (from.index(begin)!=0) &&
            (from.index(begin)!='.'); begin++);
        AsnByteArray buf = new AsnByteArray((int)siz);

        /* Step 3 */
        for (temp = val, siz = 0; temp!=0; siz++) temp >>= 7;
        int count;
        for (count = siz, temp = val; siz-- != 0; val >>=7)
        {
            byte by = (byte)((val & 0x7F) | ((temp != val)? 0x80 : 0));
            buf.setByte(by, (int)siz);
        }
        for (begin++; (begin < end) && (from.index(begin)!=0); begin++)
        {
            for (val=0; (begin < end) && (from.index(begin)!=0) && (from.index(begin)!='.');
                val = (val*10) + from.index(begin++) - '0');
            if (val == 0) siz = 1;
            else for (temp = val, siz = 0; temp != 0; siz++) temp >>=7;
            int count2;
            for (count2 = count, count += siz, temp = val; siz-- != 0; val>>=7)
            {
                byte by2 = (byte) ((val & 0x7F) | ((temp != val)? 0x80 : 0));
                buf.setByte(by2, (int)(count2+siz));
            }

        }
        lth = ((AsnOIDTableObj)obj)._write(buf, count);
        return lth;
    }

    public int vsize()
    {
        AsnByteArray array = new AsnByteArray();
        return _objidreadsize(array,0);
    }

    public int _objidreadsize(AsnByteArray to, int mode)
    {
        int holder = to.getPtr();
        int curr;
        int temp, val, siz;
        int ansr = 0;
        if (to == null) return asn_obj_err(AsnStatic.ASN_NULL_PTR);
        temp = _check_vfilled();
        if (temp <= 0) return _read_empty((int)temp, mode);
        byte by1;
        for (temp = val = 0; (((by1 = _valp.index((int)temp)) & 0x80)!=0); temp++)
            val = (val << 7) + (by1 & 0x7F);
        val = (val << 7) + _valp.index((int)temp++);
        putd(to, (val < 120) ? (val/40): 2);
        holder = to.getPtr(); // I think?  Check with Charlie...
        to.setByte((byte)'.', to.getPtr());
        to.incrPtr(1);
        putd(to, (val < 120) ? (val%40) : val - 80);
        if (mode == 0)
        {
            ansr = to.getPtr() - holder;
            to.resetPtr();
            to.incrPtr(holder);
        }
        for (siz = _valp.getLength(); temp < siz; temp++)
        {
            to.setByte((byte)'.', to.getPtr());
            to.incrPtr(1);
            byte tmp;
            for (val = 0; (((tmp=(_valp.index((int)temp))) & 0x80)!=0); temp++)
                val = (val << 7) + (tmp & 0x7F);
            val = (val << 7) + _valp.index((int)temp);
            putd(to,val);
            if (mode == 0)
            {
                ansr += to.getPtr() - holder;
                to.resetPtr();
                to.incrPtr(holder);
            }
        }
        to.setByte((byte)0, to.getPtr());
        to.incrPtr(1);
        curr = to.getPtr();
        to.resetPtr();
        to.incrPtr(holder);
        return ((mode!=0)?(curr-holder):++ansr);
    }

    public int read(AsnByteArray to)
    {
        return _objidreadsize(to, AsnStatic.ASN_READING);
    }

    protected void putd(AsnByteArray to, int val)
    {
        //recheck this
        int tmp = val / 10;
        if (tmp!=0)
            putd(to, tmp);
        byte num = (byte)((val % 10) + '0');
        to.setByte(num, to.getPtr());
        to.incrPtr(1);
        return;
    }

}
