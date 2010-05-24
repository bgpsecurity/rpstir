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
public class CRLDistributionPoints extends AsnArrayOfSequencesOf
    {
    public DistributionPoint distributionPoint = new DistributionPoint();
    public CRLDistributionPoints()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, distributionPoint, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        CRLDistributionPoints objp = new CRLDistributionPoints();
        _set_pointers(objp);
        return objp;
        }

    public CRLDistributionPoints index(int index)
        {
        return (CRLDistributionPoints)_index_op(index);
        }

    public CRLDistributionPoints set(CRLDistributionPoints frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
