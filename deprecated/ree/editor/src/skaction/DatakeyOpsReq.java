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
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class DatakeyOpsReq extends AsnInteger
    {
    public AsnObj readCIK = new AsnObj();
    public AsnObj clearCIK = new AsnObj();
    public AsnObj copyCIK = new AsnObj();
    public AsnObj readFill = new AsnObj();
    public AsnObj clearFill = new AsnObj();
    public DatakeyOpsReq()
        {
        _tag = AsnStatic.ASN_INTEGER;
        _type = (short)AsnStatic.ASN_INTEGER;
        _set_tag(readCIK, (int)1);
        _setup((AsnObj)null, readCIK, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(clearCIK, (int)0);
        _setup(readCIK, clearCIK, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(copyCIK, (int)2);
        _setup(clearCIK, copyCIK, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(readFill, (int)5);
        _setup(copyCIK, readFill, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        _set_tag(clearFill, (int)4);
        _setup(readFill, clearFill, (short)(AsnStatic.ASN_ENUM_FLAG), (int)0x0);
        }
    public DatakeyOpsReq set(DatakeyOpsReq frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
