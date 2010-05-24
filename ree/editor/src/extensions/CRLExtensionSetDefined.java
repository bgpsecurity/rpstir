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
public class CRLExtensionSetDefined extends AsnChoice
    {
    public AuthorityKeyId authKeyId = new AuthorityKeyId();
    public GeneralNames issuerAltName = new GeneralNames();
    public AsnInteger cRLNumber = new AsnInteger();
    public IssuingDistPoint issuingDistributionPoint = new IssuingDistPoint();
    public AsnInteger deltaCRLIndicator = new AsnInteger();
    public AsnNotAsn1  other = new AsnNotAsn1 ();
    public CRLExtensionSetDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, authKeyId, (short)0, (int)0x0);
        _setup(authKeyId, issuerAltName, (short)0, (int)0x0);
        _setup(issuerAltName, cRLNumber, (short)0, (int)0x0);
        _setup(cRLNumber, issuingDistributionPoint, (short)0, (int)0x0);
        _setup(issuingDistributionPoint, deltaCRLIndicator, (short)0, (int)0x0);
        _setup(deltaCRLIndicator, other, (short)0, (int)0x0);
        }
    public CRLExtensionSetDefined set(CRLExtensionSetDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
