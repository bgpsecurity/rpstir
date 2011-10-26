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

class TabListCellRenderer extends JLabel 
  implements ListCellRenderer {
  protected static Border m_noFocusBorder;
  protected FontMetrics m_fm = null;
  protected Insets m_insets = new Insets(0, 0, 0, 0);
  
  protected int m_defaultTab = 50;
  protected int[] m_tabs = null;
  
  public TabListCellRenderer(){
    super();
    m_noFocusBorder = new EmptyBorder(1, 1, 1, 1);
    setOpaque(true);
    setBorder(m_noFocusBorder);
  }
  
  public Component getListCellRendererComponent(JList list,
						Object value, 
						int index, 
						boolean isSelected, 
						boolean cellHasFocus)     {         
    setText(value.toString());
    
    setBackground(isSelected ? list.getSelectionBackground() : list.getBackground());
    setForeground(isSelected ? list.getSelectionForeground() : list.getForeground());
    
    //setEnabled(list.isEnabled());
    
    if (! list.isEnabled()) { // disable the CA name list
      setBackground(list.getBackground());
      setForeground(UIManager.getColor("Label.disabledForeground"));
    }
    //System.out.println("getListCellRendererComponent(), isEnabled(): " + list.isEnabled() 
    //		   + " isSelected: " +  isSelected + " " + value); 
    setFont(list.getFont());
    setBorder((cellHasFocus) ? UIManager.getBorder("List.focusCellHighlightBorder") : m_noFocusBorder);
    
    return this;
  }
  
  public void setDefaultTab(int defaultTab) { m_defaultTab = defaultTab; }
  
  public int getDefaultTab() { return m_defaultTab; }
  
  public void setTabs(int[] tabs) { m_tabs = tabs; }
  
  public int[] getTabs() { return m_tabs; }
  
  public int getTab(int index) {
    if (m_tabs == null)
      return m_defaultTab*index;
    
    int len = m_tabs.length;
    if (index>=0 && index<len)
      return m_tabs[index];
    
    return m_tabs[len-1] + m_defaultTab*(index-len+1);
  }
  
  
  public void paint(Graphics g) {
    m_fm = g.getFontMetrics();
    
    g.setColor(getBackground());
    g.fillRect(0, 0, getWidth(), getHeight());
    getBorder().paintBorder(this, g, 0, 0, getWidth(), getHeight());
    
    g.setColor(getForeground());
    g.setFont(getFont());
    m_insets = getInsets();
    int x = m_insets.left;
    int y = m_insets.top + m_fm.getAscent();
    
    StringTokenizer	st = new StringTokenizer(getText(), "\t");
    while (st.hasMoreTokens()) {
      String sNext = st.nextToken();
      g.drawString(sNext, x, y);
      x += m_fm.stringWidth(sNext);
      
      if (!st.hasMoreTokens())
	break;
      int index = 0;
      while (x >= getTab(index)) {
	index++;
      }
      x = getTab(index);
    }
  }
  
}

