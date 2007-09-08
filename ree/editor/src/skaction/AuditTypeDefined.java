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
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class AuditTypeDefined extends AsnChoice
    {
    public NewKeyAudit new_key = new NewKeyAudit();
    public BackupAudit backup = new BackupAudit();
    public BackupAudit restore = new BackupAudit();
    public ActivateAudit activate = new ActivateAudit();
    public CtrlMsgAudit ctrl_msg = new CtrlMsgAudit();
    public ChangeCIKAudit change_cik = new ChangeCIKAudit();
    public NameAndKeys canc_key = new NameAndKeys();
    public ClockAudit clock = new ClockAudit();
    public AuditTypeDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, new_key, (short)0, (int)0x0);
        _setup(new_key, backup, (short)0, (int)0x0);
        _setup(backup, restore, (short)0, (int)0x0);
        _setup(restore, activate, (short)0, (int)0x0);
        _setup(activate, ctrl_msg, (short)0, (int)0x0);
        _setup(ctrl_msg, change_cik, (short)0, (int)0x0);
        _setup(change_cik, canc_key, (short)0, (int)0x0);
        _setup(canc_key, clock, (short)0, (int)0x0);
        }
    public AuditTypeDefined set(AuditTypeDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
