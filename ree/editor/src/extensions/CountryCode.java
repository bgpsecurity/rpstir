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
public class CountryCode extends AsnInteger
    {
    public CountryCode()
        {
        }
    public int constraint()
        {
        AsnByteArray lo = new AsnByteArray("\001"),
            hi = new AsnByteArray("\003\347");
        int lo_lth = 1, hi_lth = 2;
        if (_num_diff(lo, lo_lth) >= 0 && _num_diff(hi, hi_lth) <= 0)
            return 1;
        return 0;
        }

    public CountryCode set(CountryCode frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
