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
public class FileData extends AsnArray
    {
    public AsnUTF8String name = new AsnUTF8String();
    public AsnAny contents = new AsnAny();
    public FileData()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)0, (int)0x0);
        _setup(name, contents, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        FileData objp = new FileData();
        _set_pointers(objp);
        return objp;
        }

    public FileData index(int index)
        {
        return (FileData)_index_op(index);
        }

    public FileData set(FileData frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
