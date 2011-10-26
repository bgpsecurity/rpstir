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
public class Extension extends AsnArray
    {
    public ExtensionSetInExtension extnID = new ExtensionSetInExtension();
    public AsnBoolean critical = new AsnBoolean();
    public ExtensionSetDefined extnValue = new ExtensionSetDefined();
    public Extension()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, extnID, (short)0, (int)0x0);
        _setup(extnID, critical, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        _setup(critical, extnValue, (short)0, (int)AsnStatic.ASN_OCTETSTRING);
        }
    public AsnObj _dup()
        {
        Extension objp = new Extension();
        _set_pointers(objp);
        return objp;
        }

    public Extension index(int index)
        {
        return (Extension)_index_op(index);
        }

    public Extension set(Extension frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
