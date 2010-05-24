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

// char sfcsid[] = "@(#)AsnTableObj.java 798E"
package asn;

import asn.*;

public class AsnTableObj extends AsnObj
{
    protected AsnByteArray wherep;  //was public in C++ -
                                  //doesn't seem like it had to be -
                                  //let's try protected

    public AsnTableObj()
    {
        wherep = null;
    }


    protected int _set_definees (int table_index)
    {
        byte holder;
        int size = wherep.getLength();
        AsnObj definee, tobj;
        int i;
        for (i=0, definee=this; true; i++)
        {
            if (i<size)
                holder = wherep.index(i);
            else holder = 0;
            if (holder == '-')
                definee = definee._go_up();
            else if (holder >= '0')
            {
                for (holder -= '0'; (holder-- != 0) && (definee !=null);
                    definee = definee._go_next());
                if (definee == null)
                    return asn_obj_err(AsnStatic.ASN_DEFINED_ERR);
                if (wherep.index(i+1) >= '0') definee = definee._go_down();
            }
            else if ((holder==' ') || (holder==0))
            {
                for (tobj = definee._go_down(); (tobj != null); tobj = tobj._go_next())
                {
                    tobj._flags &= ~(AsnStatic.ASN_CHOSEN_FLAG);
                    if ((tobj._flags & AsnStatic.ASN_FILLED_FLAG)!=0) tobj._clear(-1);
                }
                definee._flags &= ~(AsnStatic.ASN_FILLED_FLAG);
                if (table_index >= 0)
                {
                    if ((definee._flags & AsnStatic.ASN_DEFINED_FLAG)==0)
                        return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
                    if (definee._go_up()._type == AsnStatic.ASN_CHOICE)
                    {
                        definee._go_up()._flags |= AsnStatic.ASN_DEFINED_FLAG;
                        for (tobj = definee; (tobj != null); tobj=tobj._go_next())
                        {
                            tobj._flags &= ~(AsnStatic.ASN_CHOSEN_FLAG);
                            if ((tobj._flags & AsnStatic.ASN_FILLED_FLAG)!=0)
                                tobj._clear(-1);
                        }
                        definee._flags |= AsnStatic.ASN_CHOSEN_FLAG;
                    }
                    int j;
                    for (tobj = definee._go_down(), j = table_index;
                        (tobj != null) && (j-- != 0); tobj = tobj._go_next());
                    if (tobj == null) return asn_obj_err(AsnStatic.ASN_NO_DEF_ERR);
                    tobj._flags |= AsnStatic.ASN_CHOSEN_FLAG;
                    if ((tobj._type == AsnStatic.ASN_CHOICE) && (tobj._max != 0))
                    {
                        for (tobj = tobj._go_down(); tobj != null; tobj = tobj._go_next())
                        {
                            tobj._min = (tobj._go_up())._min;
                            tobj._max = (tobj._go_up())._max;
                        }
                    }
                    else if ((definee._type == AsnStatic.ASN_BOOLEAN) &&
                        ((((AsnBoolean)definee)._default & AsnStatic.BOOL_DEFINED)!=0))
                        definee.write((int)((AsnBoolean)definee)._default
                            & AsnStatic.BOOL_DEFINED);
                }
                if (holder==0) break;
                definee = this;
            }
        }
        return 1;
    }

    protected void _setup_table(AsnObj asnObj, String str, AsnObj more)
        {
	if (str.equalsIgnoreCase("0xFFFF"))
	    {
	    byte b = (byte)0xFF;
	    asnObj._valp = new AsnByteArray(2);
	    asnObj._valp.setByte(b, 0);
	    asnObj._valp.setByte(b, 1);
	    }
	else if (str.indexOf(".") > 0)
	    {
	    asnObj._valp = new AsnByteArray();
	     _convertDotNotation(asnObj._valp, str);
	    }
	else
	    {
	    asnObj._type = AsnStatic.ASN_INTEGER; /* dummy to keep write happy */
            asnObj.write(Integer.parseInt(str));
	    }
        if (more != null) asnObj._next = more;
        }
}

