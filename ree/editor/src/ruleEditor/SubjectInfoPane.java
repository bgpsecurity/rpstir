/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Marla Shepard, Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

package ruleEditor;
import ruleEditor.*;
import rules.*;
import name.*;
import asn.*;
import extensions.*;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class SubjectInfoPane extends ExtnFieldBasePane 
{
  String myType;
  RsyncPane rsyncPane;

  public SubjectInfoPane(String type) {
     super("Subject Information Access", RuleEditorData.PROHIBIT, type, false);
     myType = type;
  }

  public void setContentPane() {
    contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));
    rsyncPane = new RsyncPane(myType);
    
    contentPane.add(rsyncPane);
  }

  public int createRule(Member m) 
    {
    m.name.write("Subject Information Access");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m.rule.add();
   CompoundRule cr = (CompoundRule)m.rule.ref.sequence; // treat as seq
    int ansr = 0,
        num = rsyncPane.rsyncContents.size();
    rsyncPane.done = 0;
    rsyncPane.todo = 1;
    for (int i = 0; rsyncPane.done < num; rsyncPane.done++, i++)
        {
        cr.members.member.index(i).insert();
        Member m1 = cr.members.member.index(i);
        m1.name.write("Access Description");
        m1.tagtype.write(AsnStatic.ASN_SEQUENCE);
        m1.rule.add();
        CompoundRule cr1 = m1.rule.ref.sequence;
        cr1.members.member.index(0).insert();
        Member m11 = (Member)cr1.members.member.index(0);
        m11.name.write("Access Method");
        m11.rule.add(); 
        m11.tagtype.write(AsnStatic.ASN_OBJ_ID);
        Rule ru = (Rule)m11.rule.ref.primitive;
        ru.targets.require.target.index(0).insert();
        Target ta = ru.targets.require.target.index(0);
        ta.objid.write(ExtensionsStatic.id_ad_caRepository);
        cr1.members.member.index(1).insert();
        Member m12 = (Member)cr1.members.member.index(1);
        m12.name.write("Access Location");
        if((ansr = rsyncPane.createRule(m12)) != RuleEditorData.SUCCESS) break;
        }
    return ansr;
  }
  

  public boolean setRule(Member M) 
    {
    if (M.rule != null && M.rule.ref != null && M.rule.ref.sequence != null &&
        M.rule.ref.sequence.members != null)
        {
        Members mm = M.rule.ref.sequence.members;
        String[] ss = new String[mm.numitems()];
        for (int i = 0; i < mm.numitems(); i++)
            {
            Member m1 = mm.member.index(i); // Access Description
            if (m1.rule != null && m1.rule.ref != null && 
                m1.rule.ref.sequence != null && m1.rule.ref.sequence.members != null &&
                m1.rule.ref.sequence.members.numitems() > 1)
                {
                Member m11 = m1.rule.ref.sequence.members.member.index(1);
                if (m11.rule != null && m11.rule.ref != null && 
                    m11.rule.ref.primitive != null && 
                    m11.rule.ref.primitive.targets != null &&
                    m11.rule.ref.primitive.targets.require != null &&
                    m11.rule.ref.primitive.targets.require.numitems() > 0)
                    {
                    Targets targs = m11.rule.ref.primitive.targets.require;
                    Target ta = targs.target.index(0);
                    AsnByteArray aba = new AsnByteArray();
                    ta.read(aba);
                    ss[i] = aba.toString();
                    }
                }
            }
        rsyncPane.setRule(ss);
        }    
    return true;
    }

    public void resetContents()
    {
	rsyncPane.resetContents();
    }
}

