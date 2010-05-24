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
public class CRLEntryExtension extends AsnArray
    {
    public CRLEntryExtensionSetInCRLEntryExtension extnID = new CRLEntryExtensionSetInCRLEntryExtension();
    public AsnBoolean critical = new AsnBoolean();
    public CRLEntryExtensionSetDefined extnValue = new CRLEntryExtensionSetDefined();
    public CRLEntryExtension()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, extnID, (short)0, (int)0x0);
        _setup(extnID, critical, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _setup(critical, extnValue, (short)0, (int)AsnStatic.ASN_OCTETSTRING);
        }
    public AsnObj _dup()
        {
        CRLEntryExtension objp = new CRLEntryExtension();
        _set_pointers(objp);
        return objp;
        }

    public CRLEntryExtension index(int index)
        {
        return (CRLEntryExtension)_index_op(index);
        }

    public CRLEntryExtension set(CRLEntryExtension frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
