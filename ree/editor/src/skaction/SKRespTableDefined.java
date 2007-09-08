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
public class SKRespTableDefined extends AsnChoice
    {
    public NewKeyResp newKey = new NewKeyResp();
    public SignReq sign = new SignReq();
    public BackupResp backup = new BackupResp();
    public CtrlReq ctrl_msg = new CtrlReq();
    public ActivatedKeys restore = new ActivatedKeys();
    public AskResp ask = new AskResp();
    public SendAuditResp send_audit = new SendAuditResp();
    public AsnOctetString datakey_ops = new AsnOctetString();
    public AsnNone change_cik = new AsnNone();
    public CtrlReq cancel_key = new CtrlReq();
    public AsnNone adj_clock = new AsnNone();
    public SigOrHash download = new SigOrHash();
    public AsnOctetString ping = new AsnOctetString();
    public InitResp init = new InitResp();
    public AsnNone verify = new AsnNone();
    public ActivateKeyResp activate = new ActivateKeyResp();
    public AsnNone run_diags = new AsnNone();
    public AsnNone got_audit = new AsnNone();
    public AsnNone verify_SD = new AsnNone();
    public AsnNone loadRules = new AsnNone();
    public AsnNone key_to_fill = new AsnNone();
    public AsnNone key_from_fill = new AsnNone();
    public AskRulesResp askRules = new AskRulesResp();
    public AsnNone deleteRAs = new AsnNone();
    public AsnNone key_ops = new AsnNone();
    public SKRespTableDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, newKey, (short)0, (int)0x0);
        _setup(newKey, sign, (short)0, (int)0x0);
        _setup(sign, backup, (short)0, (int)0x0);
        _setup(backup, ctrl_msg, (short)0, (int)0x0);
        _setup(ctrl_msg, restore, (short)0, (int)0x0);
        _setup(restore, ask, (short)0, (int)0x0);
        _setup(ask, send_audit, (short)0, (int)0x0);
        _setup(send_audit, datakey_ops, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(datakey_ops, change_cik, (short)0, (int)0x0);
        _setup(change_cik, cancel_key, (short)0, (int)0x0);
        _setup(cancel_key, adj_clock, (short)0, (int)0x0);
        _setup(adj_clock, download, (short)0, (int)0x0);
        _setup(download, ping, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(ping, init, (short)0, (int)0x0);
        _setup(init, verify, (short)0, (int)0x0);
        _setup(verify, activate, (short)0, (int)0x0);
        _setup(activate, run_diags, (short)0, (int)0x0);
        _setup(run_diags, got_audit, (short)0, (int)0x0);
        _setup(got_audit, verify_SD, (short)0, (int)0x0);
        _setup(verify_SD, loadRules, (short)0, (int)0x0);
        _setup(loadRules, key_to_fill, (short)0, (int)0x0);
        _setup(key_to_fill, key_from_fill, (short)0, (int)0x0);
        _setup(key_from_fill, askRules, (short)0, (int)0x0);
        _setup(askRules, deleteRAs, (short)0, (int)0x0);
        _setup(deleteRAs, key_ops, (short)0, (int)0x0);
        }
    public SKRespTableDefined set(SKRespTableDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
