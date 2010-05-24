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
public class GeneralName extends AsnArray
    {
    public Other_name otherName = new Other_name();
    public AsnIA5String rfc822Name = new AsnIA5String();
    public AsnIA5String dNSName = new AsnIA5String();
    public ORAddress x400Address = new ORAddress();
    public Name directoryName = new Name();
    public EDIPartyName ediPartyName = new EDIPartyName();
    public AsnIA5String url = new AsnIA5String(0x86);
    public AsnOctetString iPAddress = new AsnOctetString();
    public AsnObjectIdentifier registeredID = new AsnObjectIdentifier();
    public GeneralName()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, otherName, (short)0, (int)0xA0);
        _setup(otherName, rfc822Name, (short)0, (int)0x81);
        _setup(rfc822Name, dNSName, (short)0, (int)0x82);
        _setup(dNSName, x400Address, (short)0, (int)0xA3);
        _setup(x400Address, directoryName, (short)0, (int)0xA4);
        _setup(directoryName, ediPartyName, (short)0, (int)0xA5);
        _setup(ediPartyName, url, (short)0, (int)0x86);
        _setup(url, iPAddress, (short)0, (int)0x87);
        _setup(iPAddress, registeredID, (short)0, (int)0x88);
        }
    public AsnObj _dup()
        {
        GeneralName objp = new GeneralName();
        _set_pointers(objp);
        return objp;
        }

    public GeneralName index(int index)
        {
        return (GeneralName)_index_op(index);
        }

    public GeneralName set(GeneralName frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
