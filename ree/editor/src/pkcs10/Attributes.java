/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
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
package pkcs10;
import certificate.*;
import name.*;
import Algorithms.*;
import asn.*;
public class Attributes extends AsnArrayOfSetsOf
    {
    public Attribute_PKCS10 attribute_PKCS10 = new Attribute_PKCS10();
    public Attributes()
        {
        _setup((AsnObj)null, attribute_PKCS10, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        Attributes objp = new Attributes();
        _set_pointers(objp);
        return objp;
        }

    public Attributes index(int index)
        {
        return (Attributes)_index_op(index);
        }

    public Attributes set(Attributes frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
