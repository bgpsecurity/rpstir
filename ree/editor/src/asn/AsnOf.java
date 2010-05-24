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

// char sfcsid[] = "@(#)AsnOf.java 659E"
package asn;

import asn.*;

public class AsnOf extends AsnObj
    {
    public AsnOf()
        {
        _flags |= AsnStatic.ASN_OF_FLAG;
        }

    public void set(AsnOf asnOf)
        {
        //check this one with Charlie
        int map_num;
        AsnObj fsub, ntsub, tsub;

        if ((_flags & AsnStatic.ASN_FILLED_FLAG)!=0) clear();
        for (fsub = (AsnArray)asnOf._sub, tsub = (AsnArray)_sub, map_num=0;
            (fsub != null) && (((AsnOf)fsub)._next != null);
            fsub = ((AsnOf)fsub)._next, map_num++)
            {
            if ((_max != 0) && (map_num > _max))
                {
                asn_obj_err(AsnStatic.ASN_OF_BOUNDS_ERR);
                return;
                }
            ntsub = (AsnObj)((AsnArray)tsub)._dup();
            if (((AsnOf)tsub)._next == null)
                {
                ((AsnOf)ntsub)._next = tsub;
                _sub = ntsub;
                }
            else
                {
                ((AsnOf)ntsub)._next = ((AsnOf)tsub)._next;
                ((AsnOf)tsub)._next = ntsub;
                }
            tsub = ntsub;
            tsub.set(fsub);
            }
        _fill_upward(AsnStatic.ASN_FILLED_FLAG);
        }
    }

