/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.Component;

import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.TreePath;

import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.tasks.Model;

/**
 * Provides a dialog for selecting a CA.
 * The dialog displays the CA hierarchy as a tree
 *
 * @author tomlinso
 */
public class CAChooser {
  private final CATreeModel treeModel;
  private final JTree tree;
  /**
   * @param model
   * @param ca
   */
  public CAChooser(Model model, CA_Object ca) {
    CA_Object rootCA = model.getRootCA();
    treeModel = new CATreeModel(rootCA);
    tree = new JTree(treeModel);
    CA_Object[] path = getPathToRoot(rootCA, ca, 0);
    tree.setSelectionPath(new TreePath(path));
  }

  /**
   * @param ca
   * @param depth
   * @return
   */
  private CA_Object[] getPathToRoot(CA_Object rootCA, CA_Object ca, int depth) {
    CA_Object[] ret;
    if (ca == rootCA) {
      ret = new CA_Object[depth + 1];
    } else {
      ret = getPathToRoot(rootCA, ca.getParent(), depth + 1);
    }
    ret[ret.length - depth - 1] = ca;
    return ret;
  }

  /**
   * @param c
   * @return the selected CA_Object or null for no selection
   */
  public CA_Object showDialog(Component c) {
    JScrollPane scrollPane = new JScrollPane(tree);
    JOptionPane optionPane =
      new JOptionPane(scrollPane,
                      JOptionPane.QUESTION_MESSAGE,
                      JOptionPane.OK_CANCEL_OPTION,
                      null, null, null);
    JDialog dialog = optionPane.createDialog(c, "Select a CA");
    dialog.setResizable(true);
    dialog.setVisible(true);
    dialog.dispose();
    Object value = optionPane.getValue();
    // Should be Integer unless aborted
    if (value != null) {
      int option = (Integer) value;
      if (option == JOptionPane.OK_OPTION) {
        TreePath selectionPath = tree.getSelectionPath();
        if (selectionPath != null) {
          return (CA_Object) selectionPath.getLastPathComponent();
        }
      }
    }
    return null;
  }
}
