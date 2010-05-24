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
public class IssuingDistPoint extends AsnArray
    {
    public DistributionPointName distributionPoint = new DistributionPointName();
    public AsnBoolean onlyContainsUserCerts = new AsnBoolean();
    public AsnBoolean onlyContainsCACerts = new AsnBoolean();
    public ReasonFlags onlySomeReasons = new ReasonFlags();
    public AsnBoolean indirectCRL = new AsnBoolean();
    public IssuingDistPoint()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, distributionPoint, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA0);
        _setup(distributionPoint, onlyContainsUserCerts, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x81);
        _setup(onlyContainsUserCerts, onlyContainsCACerts, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x82);
        _setup(onlyContainsCACerts, onlySomeReasons, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x83);
        _setup(onlySomeReasons, indirectCRL, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x84);
        }
    public AsnObj _dup()
        {
        IssuingDistPoint objp = new IssuingDistPoint();
        _set_pointers(objp);
        return objp;
        }

    public IssuingDistPoint index(int index)
        {
        return (IssuingDistPoint)_index_op(index);
        }

    public IssuingDistPoint set(IssuingDistPoint frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
