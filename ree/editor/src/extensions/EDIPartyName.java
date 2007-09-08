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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class EDIPartyName extends AsnSequence
    {
    public DirectoryString nameAssigner = new DirectoryString();
    public DirectoryString partyName = new DirectoryString();
    public EDIPartyName()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, nameAssigner, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0xA0);
        _setup(nameAssigner, partyName, (short)0, (int)0xA1);
        }
    public EDIPartyName set(EDIPartyName frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
