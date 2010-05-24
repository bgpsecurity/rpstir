/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
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
package pkcs10;
import certificate.*;
import name.*;
import Algorithms.*;
import asn.*;
public class TableInAttribute_PKCS10 extends Table
    {
    public TableInAttribute_PKCS10()
        {
        wherep = new AsnByteArray("1");
        }
    public int set(AsnByteArray c)
        {
        return write(c);
        }
    }
