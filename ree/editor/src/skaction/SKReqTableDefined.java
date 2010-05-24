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
public class SKReqTableDefined extends AsnChoice
    {
    public NewKeyReq newKey = new NewKeyReq();
    public SignReq sign = new SignReq();
    public BackupReq backup = new BackupReq();
    public CtrlReq ctrl_msg = new CtrlReq();
    public RestoreReq restore = new RestoreReq();
    public AsnNone ask = new AsnNone();
    public AsnGeneralizedTime send_audit = new AsnGeneralizedTime();
    public DatakeyOpsReq datakey_ops = new DatakeyOpsReq();
    public ChangeCIKReq change_cik = new ChangeCIKReq();
    public NameAndKeys cancel_key = new NameAndKeys();
    public AsnGeneralizedTime adj_clock = new AsnGeneralizedTime();
    public DownloadReq download = new DownloadReq();
    public AsnOctetString ping = new AsnOctetString();
    public InitReq init = new InitReq();
    public VerifyReq verify = new VerifyReq();
    public NameAndKeys activate = new NameAndKeys();
    public RunDiagsReq run_diags = new RunDiagsReq();
    public AsnNone got_audit = new AsnNone();
    public VerifySDReq verifySD = new VerifySDReq();
    public LoadRulesReq loadRules = new LoadRulesReq();
    public KeyToFillReq key_to_fill = new KeyToFillReq();
    public KeyFromFillReq key_from_fill = new KeyFromFillReq();
    public AskRulesReq askRules = new AskRulesReq();
    public DeleteRulesReq deleteRules = new DeleteRulesReq();
    public KeyOpsReq key_ops = new KeyOpsReq();
    public SKReqTableDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, newKey, (short)0, (int)0x0);
        _setup(newKey, sign, (short)0, (int)0x0);
        _setup(sign, backup, (short)0, (int)0x0);
        _setup(backup, ctrl_msg, (short)0, (int)0x0);
        _setup(ctrl_msg, restore, (short)0, (int)0x0);
        _setup(restore, ask, (short)0, (int)0x0);
        _setup(ask, send_audit, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(send_audit, datakey_ops, (short)0, (int)0x0);
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
        _setup(got_audit, verifySD, (short)0, (int)0x0);
        _setup(verifySD, loadRules, (short)0, (int)0x0);
        _setup(loadRules, key_to_fill, (short)0, (int)0x0);
        _setup(key_to_fill, key_from_fill, (short)0, (int)0x0);
        _setup(key_from_fill, askRules, (short)0, (int)0x0);
        _setup(askRules, deleteRules, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(deleteRules, key_ops, (short)0, (int)0x0);
        }
    public SKReqTableDefined set(SKReqTableDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
