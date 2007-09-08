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

// char sfcsid[] = "@(#)AsnNumeric.java 622E"
package asn;

import asn.*;

public class AsnNumeric extends AsnObj
{
    public AsnNumeric()
    {
    }

    public int _compare(AsnNumeric obj)
    {
        int ansr;
        int minus = 0;
        if ((_valp.index(0) & 0x80)!=0)
        {
            if ((obj._valp.index(0) & 0x80)!=0) minus=1;
            else return -1;
        }
        else if ((obj._valp.index(0) & 0x80)!=0) return 1;
        int lth1 = vsize();
        int lth2 = obj.vsize();
        if (lth1 < lth2) ansr = -1;
        else if (lth1 > lth2) ansr = 1;
        else
        {
            for (ansr=0; (ansr<lth1) &&
                (_valp.index(ansr) == obj._valp.index(ansr)); ansr++);
            if (ansr>=lth1) return 0;
            if (_valp.index(ansr) < obj._valp.index(ansr)) ansr = -1;
            else ansr = 1;
        }
        if (minus != 0) ansr = -ansr;
        return ansr;
    }



}
