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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class CRLEntryExtensionSetDefined extends AsnChoice
    {
    public CRLReason reasonCode = new CRLReason();
    public AsnGeneralizedTime invalidityDate = new AsnGeneralizedTime();
    public AsnObjectIdentifier instructionCode = new AsnObjectIdentifier();
    public GeneralNames certificateIssuer = new GeneralNames();
    public AsnNotAsn1  other = new AsnNotAsn1 ();
    public CRLEntryExtensionSetDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, reasonCode, (short)0, (int)0x0);
        _setup(reasonCode, invalidityDate, (short)0, (int)0x0);
        _setup(invalidityDate, instructionCode, (short)0, (int)0x0);
        _setup(instructionCode, certificateIssuer, (short)0, (int)0x0);
        _setup(certificateIssuer, other, (short)0, (int)0x0);
        }
    public CRLEntryExtensionSetDefined set(CRLEntryExtensionSetDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
