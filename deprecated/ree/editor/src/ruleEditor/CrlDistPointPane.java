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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

public class CrlDistPointPane extends ExtnFieldBasePane 
{
  String myType;
  RsyncPane rsyncPane;

  public CrlDistPointPane(String type) {
     super("Crl Distribution Points", RuleEditorData.PROHIBIT, type, false);
     myType = type;
     if (type.compareTo("CRL") == 0)
	 rsyncPane.setDisabled();
  }

  public void setContentPane() {
    boolean edit = true;;
    contentPane.setLayout(new BoxLayout(contentPane, BoxLayout.Y_AXIS));
    rsyncPane = new RsyncPane(myType);
    contentPane.add(rsyncPane);
  }

  public int createRule(Member m) 
    {
    // System.out.println("CRL Dist Point rule");
    m.name.write("CRL Distribution Points");
    m.tagtype.write(AsnStatic.ASN_SEQUENCE);
    m.rule.add();
    SetSeqOfRule sso = (SetSeqOfRule)m.rule.ref.seqOf;
    sso.min.write(1);
    sso.max.write(1);
    sso.member.name.write(RuleEditorData.DISTRIBUTION_POINT);
    sso.member.tagtype.write(AsnStatic.ASN_SEQUENCE);
    sso.member.rule.add();
    CompoundRule cr = sso.member.rule.ref.sequence;
    cr.members.member.index(0).insert();
    Member m1 = (Member)cr.members.member.index(0);
    m1.name.write(RuleEditorData.DISTRIBUTION_POINT_NAME);
    m1.tagtype.write(AsnStatic.ASN_CONT_CONSTR);
    m1.rule.add();
    CompoundRule cr1 = (CompoundRule)m1.rule.ref.sequence;
    cr1.members.member.index(0).insert();
    Member m11 = (Member)cr1.members.member.index(0);
    m11.name.write(RuleEditorData.GENERAL_NAMES);
    m11.tagtype.write(AsnStatic.ASN_CONT_CONSTR); 
    rsyncPane.done = 0;
    rsyncPane.todo = 1;
    m11.rule.add();
    CompoundRule cr2 = m11.rule.ref.sequence;
    int ansr = 0;
    for (int i = 0, num = rsyncPane.rsyncContents.size();
        rsyncPane.done < num; rsyncPane.done++, i++)
        {
//    System.out.println("GenName " + i + " num " + num);
        cr2.members.member.index(i).insert();
        Member m111 = (Member)cr2.members.member.index(i); 
        m111.name.write(RuleEditorData.GENERAL_NAME);
        if ((ansr = rsyncPane.createRule(m111)) != RuleEditorData.SUCCESS) 
            break;
        }
    return ansr;
    }
  
  

  public boolean setRule(Member M) 
    {
    //System.out.println("in crl set rule.");
    if (M.rule != null && M.rule.ref != null && M.rule.ref.seqOf != null &&
        M.rule.ref.seqOf.member != null)
        {
        Member m1 = M.rule.ref.seqOf.member;  // Distribution Point
        if (m1.rule != null && m1.rule.ref != null && m1.rule.ref.sequence != null &&
            m1.rule.ref.sequence != null && m1.rule.ref.sequence.members != null )
            {
            Member m11 = m1.rule.ref.sequence.members.member.index(0); // Dist Point Name
            if (m11.rule != null && m11.rule.ref != null && 
                m11.rule.ref.sequence != null && m11.rule.ref.sequence.members != null &&
                m11.rule.ref.sequence.members.numitems() > 0)
                {
                Member m111 = m11.rule.ref.sequence.members.member.index(0); // Gen names
                if (m111.rule != null && m111.rule.ref != null && 
                    m111.rule.ref.sequence != null && 
                    m111.rule.ref.sequence.members != null)
                    {
                    Members mm1 = m111.rule.ref.sequence.members;
                    String[] ss = new String[mm1.numitems()];
                    //System.out.println("Number of points " + mm1.numitems());
                    for (int i = 0; i < mm1.numitems(); i++)
                        {
                        Member m111i = mm1.member.index(i);
                        if (m111i.rule != null && m111i.rule.ref != null &&
                            m111i.rule.ref.primitive != null &&
                            m111i.rule.ref.primitive.targets != null &&
                            m111i.rule.ref.primitive.targets.require != null)
                            {
                            Targets targs = m111i.rule.ref.primitive.targets.require;
                            Target ta = targs.target.index(0);
                            AsnByteArray aba = new AsnByteArray();
                            ta.value.read(aba);
                            ss[i] = aba.toString();
                            }
                        }
                    rsyncPane.setRule(ss);
                    }
                }
            }
        } 
    return true;
    }


    public void resetContents()
    {
	rsyncPane.resetContents();
    }
}

