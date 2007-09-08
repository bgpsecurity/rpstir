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

// char sfcsid[] = "@(#)AsnTime.java 679E"
package asn;

import asn.*;

public class AsnTime extends AsnObj
{
    public AsnTime()
    {
        //empty
    }

    public int read(AsnIntRef to)
    {
        int len = _valp.relativeLength();  //check if should be length or relative length?
        AsnByteArray array = new AsnByteArray(_valp);
        //get the array, or just send in the whole thing??
        if (_type == AsnStatic.ASN_GENTIME)
        {
            len -= 2;
            array.incrPtr(2);
        }

        to.val = _get_asn_time(array, len);
        if (to.val == 0xFFFFFFFF)
            return asn_obj_err(AsnStatic.ASN_TIME_ERR);
        return len;
    }

    public int write(int val)
    {
        //CHECK THIS FUNCTION WITH CHARLIE!!!
        AsnByteArray buf = new AsnByteArray();
        int count = (_type == AsnStatic.ASN_GENTIME) ? 2 : 0;
        AsnByteArray tempc = new AsnByteArray();
        int i;
        i = _put_asn_time(tempc, val);
        if (i < 0) return asn_obj_err(AsnStatic.ASN_TIME_ERR);
        if (count > 0)
        {
            String str = (tempc.index(0) >= '7') ? "19" : "20";
            buf.append(str.getBytes(), 2);
            i+=2;
        }
        buf.append(tempc);
        return (int)(write(buf, i));
    }

   public int _compare(AsnTime obj)
    {
        AsnIntRef bb = new AsnIntRef(0),
            cc = new AsnIntRef(0);;
        read(bb);
        obj.read(cc);
        if (bb.val == cc.val) return 0;
        return ((bb.val < cc.val) ? -1 : 1);
    }




}
