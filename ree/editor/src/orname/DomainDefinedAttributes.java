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
package orname;
import name.*;
import asn.*;
public class DomainDefinedAttributes extends AsnSequenceOf
    {
    public DomainDefinedAttribute domainDefinedAttribute = new DomainDefinedAttribute();
    public DomainDefinedAttributes()
        {
        _min = 1;
        _max = 4;
        _setup((AsnObj)null, domainDefinedAttribute, (short)0, (int)0x0);
        }
    public DomainDefinedAttributes set(DomainDefinedAttributes frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
