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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class DistributionPointName extends AsnArray
    {
    public GeneralNames fullName = new GeneralNames();
    public RelativeDistinguishedName nameRelativeToCRLIssuer = new RelativeDistinguishedName();
    public DistributionPointName()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, fullName, (short)0, (int)0xA0);
        _setup(fullName, nameRelativeToCRLIssuer, (short)0, (int)0xA1);
        }
    public AsnObj _dup()
        {
        DistributionPointName objp = new DistributionPointName();
        _set_pointers(objp);
        return objp;
        }

    public DistributionPointName index(int index)
        {
        return (DistributionPointName)_index_op(index);
        }

    public DistributionPointName set(DistributionPointName frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
