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
package rules;
import name.*;
import asn.*;
public class Range extends AsnArray
    {
    public RangeLimit lo = new RangeLimit();
    public RangeLimit hi = new RangeLimit();
    public AsnInteger maxsiz = new AsnInteger();
    public Range()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, lo, (short)0, (int)0x0);
        _setup(lo, hi, (short)0, (int)0x0);
        _setup(hi, maxsiz, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        Range objp = new Range();
        _set_pointers(objp);
        return objp;
        }

    public Range index(int index)
        {
        return (Range)_index_op(index);
        }

    public Range set(Range frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
