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

// char sfcsid[] = "@(#)AsnChoice.java 622E"
package asn;

import asn.*;

public class AsnChoice extends AsnObj
{
    public AsnChoice()
    {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
    }

    public boolean equals(AsnChoice asnChoice)
    {
        AsnObj lsub, rsub;
        if  ((this._flags & AsnStatic.ASN_DEFINED_FLAG) !=
            (asnChoice._flags & AsnStatic.ASN_DEFINED_FLAG))
            {
                asn_obj_err(AsnStatic.ASN_MATCH_ERR);
                return false;
            }
        if (((this._flags & AsnStatic.ASN_FILLED_FLAG)==0) &&
            ((asnChoice._flags & AsnStatic.ASN_FILLED_FLAG)==0))
            return true;
        for (lsub=this; ((lsub=lsub._check_choice())!=null) &&
            (lsub._type==AsnStatic.ASN_CHOICE); );
        for (rsub=asnChoice; ((rsub=rsub._check_choice())!=null) &&
            (rsub._type==AsnStatic.ASN_CHOICE); );
        if ((lsub==null) != (rsub==null))
            return false;
        if (lsub == null)
            return true;
        return lsub.equals(rsub);
    }

    public void set(AsnChoice asnChoice)
    {
        AsnChoice fsub, tsub;
        if ((this._flags & AsnStatic.ASN_DEFINED_FLAG) !=
            (asnChoice._flags & AsnStatic.ASN_DEFINED_FLAG))
        {
            asn_obj_err(AsnStatic.ASN_MATCH_ERR);
            return;
        }
        int flag = ((this._flags & AsnStatic.ASN_DEFINED_FLAG)!=0) ?
            AsnStatic.ASN_CHOSEN_FLAG : AsnStatic.ASN_FILLED_FLAG;
        for (fsub = (AsnChoice)asnChoice._sub; (fsub != null) && ((fsub._flags & flag)==0);
            fsub = (AsnChoice)fsub._next);
        if (fsub == null) return;
        if ((this._flags & AsnStatic.ASN_DEFINED_FLAG)==0)
        {
            for (tsub = (AsnChoice)this._sub; (tsub != null) && (tsub._tag != fsub._tag);
                tsub = (AsnChoice)tsub._next);
        }
        else for (tsub = (AsnChoice)this._sub; (tsub != null) && ((tsub._flags & flag)==0);
                tsub = (AsnChoice)tsub._next);
        if (tsub == null) return;
        ((AsnObj)tsub).set((AsnObj)fsub);
    }

}
