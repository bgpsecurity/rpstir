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
public class CRLExtension extends AsnArray
    {
    public CRLExtensionSetInCRLExtension extnID = new CRLExtensionSetInCRLExtension();
    public AsnBoolean critical = new AsnBoolean();
    public CRLExtensionSetDefined extnValue = new CRLExtensionSetDefined();
    public CRLExtension()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, extnID, (short)0, (int)0x0);
        _setup(extnID, critical, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _setup(critical, extnValue, (short)0, (int)AsnStatic.ASN_OCTETSTRING);
        }
    public AsnObj _dup()
        {
        CRLExtension objp = new CRLExtension();
        _set_pointers(objp);
        return objp;
        }

    public CRLExtension index(int index)
        {
        return (CRLExtension)_index_op(index);
        }

    public CRLExtension set(CRLExtension frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
