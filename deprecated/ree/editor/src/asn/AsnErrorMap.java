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

// char sfcsid[] = "@(#)AsnErrorMap.java 622E"
package asn;

public class AsnErrorMap
{

    private static int asn_errno;
    private static AsnObj asn_err_ptr;
    public static String asn_map_string;
    private static Integer asn_constraint_ptr;
    private static AsnErrorMap instance = null;  // What for? allow one for one exec?

    public static AsnErrorMap instance()
    {
        if (instance == null)
            instance = new AsnErrorMap();
        return instance;
    }

    private AsnErrorMap()
    {
        asn_constraint_ptr = null;
        asn_err_ptr = null;
        asn_errno = 0;
        asn_map_string = null;
    }

    public AsnObj getErrorPtr()
    {
        return asn_err_ptr;
    }

    public int getErrorNo()
    {
        return asn_errno;
    }

    public Integer getConstraintPtr()
    {
        return asn_constraint_ptr;
    }

    public void setErrorPtr(AsnObj value)
    {
        asn_err_ptr = value;
    }

    public void setErrorNo(int value)
    {
        asn_errno = value;
    }

    public void setConstraintPtr(Integer value)
    {
        asn_constraint_ptr = value;
    }

}

