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

// char sfcsid[] = "@(#)AsnBoolean.java 622E"
package asn;

public class AsnBoolean extends AsnNumeric
{
    protected short _default;

    public AsnBoolean()
    {
        _tag = AsnStatic.ASN_BOOLEAN;
        _type = (short)AsnStatic.ASN_BOOLEAN;
        _default = 0;
    }

    public void _set_def(int value)
    {
        _default = (short)value;
    }

    public int _get_def()
    {
        return _default;
    }

    public void set(int val)
    {
        write(val);
    }

    public int constraint()
    {
        //check if there is a constraint and if it is noted correctly
        byte val = 0;
        if (_valp != null)
            val = _valp.index(0);
        if ( ((_default & AsnStatic.BOOL_DEFINED)==0) ||
            (val == 0) == ((_default & AsnStatic.BOOL_DEFINED_VAL) == 0))
            return 1;
        return 0;
    }

}
