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
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class ActivatedKey extends AsnArray
    {
    public AsnOctetString keyName = new AsnOctetString();
    public SubjectPublicKeyInfo results = new SubjectPublicKeyInfo();
    public ActivatedKey()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, keyName, (short)0, (int)0x0);
        keyName._boundset(1, 16);
        _setup(keyName, results, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        ActivatedKey objp = new ActivatedKey();
        _set_pointers(objp);
        return objp;
        }

    public ActivatedKey index(int index)
        {
        return (ActivatedKey)_index_op(index);
        }

    public ActivatedKey set(ActivatedKey frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
