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
public class DistributionPoint extends AsnArray
    {
    public DistributionPointName distributionPoint = new DistributionPointName();
    public ReasonFlags reasons = new ReasonFlags();
    public GeneralNames cRLIssuer = new GeneralNames();
    public DistributionPoint()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, distributionPoint, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA0);
        _setup(distributionPoint, reasons, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x81);
        _setup(reasons, cRLIssuer, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA2);
        }
    public AsnObj _dup()
        {
        DistributionPoint objp = new DistributionPoint();
        _set_pointers(objp);
        return objp;
        }

    public DistributionPoint index(int index)
        {
        return (DistributionPoint)_index_op(index);
        }

    public DistributionPoint set(DistributionPoint frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
