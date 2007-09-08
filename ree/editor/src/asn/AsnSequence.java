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

// char sfcsid[] = "@(#)AsnSequence.java 622E"
package asn;

import asn.*;

public class AsnSequence extends AsnObj
{
    public AsnSequence()
    {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
    }

    public void set(AsnSequence obj)
    {
        AsnObj fsub, tsub;
        if ((_flags & AsnStatic.ASN_FILLED_FLAG) != 0)
            clear();
        for (fsub = obj._sub, tsub = _sub; (tsub!=null) && (fsub!=null); fsub =
            ((AsnSequence)fsub)._next, tsub = ((AsnSequence)tsub)._next)
        {
            tsub.set(fsub);
        }
    }

    public boolean equals(AsnSequence obj)
    {
        boolean ansr = true;
        AsnObj rsub, lsub;
        for (rsub = obj._sub, lsub = _sub; (lsub!=null) && (rsub!=null) &&
            (ansr=(lsub.equals(rsub))); rsub = ((AsnSequence)rsub)._next,
            lsub = ((AsnSequence)lsub)._next);
        if (ansr == false) return ansr;
        if ((lsub!=null) || (rsub!=null)) return false;
        return true;
    }

}
