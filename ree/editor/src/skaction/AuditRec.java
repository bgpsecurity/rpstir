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
public class AuditRec extends AsnArray
    {
    public AsnGeneralizedTime date_time = new AsnGeneralizedTime();
    public AuditTypeInAuditRec typ = new AuditTypeInAuditRec();
    public AuditTypeDefined rec = new AuditTypeDefined();
    public AsnInteger error = new AsnInteger();
    public AuditRec()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, date_time, (short)0, (int)0x0);
        _setup(date_time, typ, (short)0, (int)0x0);
        _setup(typ, rec, (short)0, (int)0x0);
        _setup(rec, error, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_DEFAULT_FLAG), (int)0x0);
        error._set_def(0);
        }
    public AsnObj _dup()
        {
        AuditRec objp = new AuditRec();
        _set_pointers(objp);
        return objp;
        }

    public AuditRec index(int index)
        {
        return (AuditRec)_index_op(index);
        }

    public AuditRec set(AuditRec frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
