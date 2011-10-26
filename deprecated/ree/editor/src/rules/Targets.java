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
public class Targets extends AsnSequenceOf
    {
    public Target target = new Target();
    public Targets()
        {
        _min = 0;
        _max = 2147483647;
        _setup((AsnObj)null, target, (short)0, (int)0x0);
        }
    public Targets set(Targets frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
