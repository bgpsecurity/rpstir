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

// char sfcsid[] = "@(#)AsnArrayOfSets.java 659E"
package asn;

import asn.*;

public class AsnArrayOfSets extends AsnSet implements AsnArrayInterface
{
    public AsnArrayOfSets()
    {
    }

    public int remove()
    {
        // This method is derived from interface asn.AsnArrayInterface
        // to do: code goes here
        return _remove();
    }

    public int insert()
    {
        // This method is derived from interface asn.AsnArrayInterface
        // to do: code goes here
        return _insert();
    }

    public AsnArrayOfSets index(int val)
        {
        return (AsnArrayOfSets)(_index_op(val));
        }
    }

