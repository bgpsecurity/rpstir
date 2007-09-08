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
package name;
import asn.*;
public class DirectoryString extends AsnArray
    {
    public AsnPrintableString printableString = new AsnPrintableString();
    public AsnTeletexString teletexString = new AsnTeletexString();
    public AsnUniversalString universalString = new AsnUniversalString();
    public AsnBMPString bMPString = new AsnBMPString();
    public DirectoryString()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, printableString, (short)0, (int)0x0);
        printableString._boundset(1, 64);
        _setup(printableString, teletexString, (short)0, (int)0x0);
        teletexString._boundset(1, 64);
        _setup(teletexString, universalString, (short)0, (int)0x0);
        universalString._boundset(1, 64);
        _setup(universalString, bMPString, (short)0, (int)0x0);
        }
    public AsnObj _dup()
        {
        DirectoryString objp = new DirectoryString();
        _set_pointers(objp);
        return objp;
        }

    public DirectoryString index(int index)
        {
        return (DirectoryString)_index_op(index);
        }

    public DirectoryString set(DirectoryString frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
