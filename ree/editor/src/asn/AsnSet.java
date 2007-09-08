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

// char sfcsid[] = "@(#)AsnSet.java 622E"
package asn;

import asn.*;

public class AsnSet extends AsnObj
{
    protected AsnLink _relinksp;

    public AsnSet()
    {
        _tag = AsnStatic.ASN_SET;
        _type = (short)AsnStatic.ASN_SET;
        _relinksp = null;
    }

    public void set(AsnSet obj)
    {
        if ((_flags & AsnStatic.ASN_FILLED_FLAG) != 0)
            clear();
        for (AsnLink link = obj._relinksp; (link != null); link = link._next)
        {
            AsnObj sub;
            for (sub = _sub; (sub!=null) &&
                (((AsnSet)sub)._tag !=link.obj._tag); sub = ((AsnSet)sub)._next);
            add_link(sub);
            sub.set(link.obj);
        }
    }

    public void add_link(AsnObj obj)
    {
        AsnLink link = _relinksp;
        if (_relinksp == null)
        {
            _relinksp = new AsnLink();
            link = _relinksp;
        }
        else
        {
            for ( ; (link._next != null) && (link.obj != obj); link = link._next);
            if (link.obj != obj)
            {
                link._next = new AsnLink();
                link = link._next;
            }
        }
        link.obj = obj;
    }

}
