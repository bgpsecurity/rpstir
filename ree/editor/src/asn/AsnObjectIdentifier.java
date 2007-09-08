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

// char sfcsid[] = "@(#)AsnObjectIdentifier.java 663E"
package asn;

import asn.*;

public class AsnObjectIdentifier extends AsnObj
{
    public AsnObjectIdentifier()
    {
        _tag = AsnStatic.ASN_OBJ_ID;
        _type = (short)AsnStatic.ASN_OBJ_ID;
    }

    public int read(AsnByteArray to)
    {
        return _objidreadsize(to, AsnStatic.ASN_READING);
    }

    public int vsize()
    {
        AsnByteArray array = new AsnByteArray();
        return _objidreadsize(array,0);
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

    public void set(AsnByteArray value)
    {
        write(value, (int)(value.getLength()));
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
