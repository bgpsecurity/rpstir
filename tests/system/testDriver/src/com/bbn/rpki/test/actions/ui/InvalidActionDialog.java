/*
 * Created on Nov 12, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.Component;
import java.util.List;

import javax.swing.JOptionPane;

import com.bbn.rpki.test.actions.AbstractAction;

/**
 * <Enter the description of this type here>
 *
 * @author rtomlinson
 */
public class InvalidActionDialog {

  /**
   * Check the validity of an AbstractAction and post a message if not valid
   */
  public static boolean checkValidity(Component c, AbstractAction action) {
    List<String> invalidReasons = action != null ? action.getInvalidReasons() : null;
    if (invalidReasons != null) {
      Object[] msg = new Object[invalidReasons.size() + 1];
      msg[0] = "Please fix the following problems:";
      for (int i = 0; i < invalidReasons.size(); i++) {
        msg[i + 1] = "   " + invalidReasons.get(i);
      };
      JOptionPane.showMessageDialog(c, msg, "Invalid Action Attributes", JOptionPane.ERROR_MESSAGE);
      return false;
    }
    return true;
  }

}
