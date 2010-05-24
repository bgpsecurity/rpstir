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
package rules;
import name.*;
import asn.*;
public class GroupRule extends AsnArray
    {
    public AsnUTF8String name = new AsnUTF8String();
    public GroupSubRule ifcase = new GroupSubRule();
    public GroupSubRule thencase = new GroupSubRule();
    public GroupRule()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, name, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(name, ifcase, (short)0, (int)0x0);
        _setup(ifcase, thencase, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        GroupRule objp = new GroupRule();
        _set_pointers(objp);
        return objp;
        }

    public GroupRule index(int index)
        {
        return (GroupRule)_index_op(index);
        }

    public GroupRule set(GroupRule frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
