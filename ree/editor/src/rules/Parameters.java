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
public class Parameters extends AsnSequenceOf
    {
    public AsnNumericArray array = new AsnNumericArray();
    public Parameters()
        {
        _setup((AsnObj)null, array, (short)0, (int)0x0);
        }
    public Parameters set(Parameters frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
