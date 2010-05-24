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
public class CRLReason extends AsnNumericArray
    {
    public AsnObj unspecified = new AsnObj();
    public AsnObj keyCompromised = new AsnObj();
    public AsnObj caCompromised = new AsnObj();
    public AsnObj affiliationChanged = new AsnObj();
    public AsnObj superseded = new AsnObj();
    public AsnObj cessationOfOperation = new AsnObj();
    public AsnObj certificateHold = new AsnObj();
    public AsnObj certHoldRelease = new AsnObj();
    public AsnObj removeFromCRL = new AsnObj();
    public CRLReason()
        {
        _tag = AsnStatic.ASN_ENUMERATED;
        _type = (short)AsnStatic.ASN_ENUMERATED;
        _set_tag(unspecified, (int)0);
        _setup((AsnObj)null, unspecified, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(keyCompromised, (int)1);
        _setup(unspecified, keyCompromised, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(caCompromised, (int)2);
        _setup(keyCompromised, caCompromised, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(affiliationChanged, (int)3);
        _setup(caCompromised, affiliationChanged, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(superseded, (int)4);
        _setup(affiliationChanged, superseded, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(cessationOfOperation, (int)5);
        _setup(superseded, cessationOfOperation, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(certificateHold, (int)6);
        _setup(cessationOfOperation, certificateHold, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(certHoldRelease, (int)7);
        _setup(certificateHold, certHoldRelease, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(removeFromCRL, (int)8);
        _setup(certHoldRelease, removeFromCRL, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        CRLReason objp = new CRLReason();
        _set_pointers(objp);
        return objp;
        }

    public CRLReason index(int index)
        {
        return (CRLReason)_index_op(index);
        }

    public CRLReason set(CRLReason frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
