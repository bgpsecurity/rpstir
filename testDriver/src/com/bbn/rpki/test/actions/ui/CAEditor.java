/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dialog.ModalityType;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.util.Collection;
import java.util.HashSet;

import javax.swing.Action;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.tasks.Model;

/**
 * Provides a dialog for selecting a CA.
 * The dialog displays the CA hierarchy as a tree
 *
 * @author tomlinso
 */
public class CAEditor implements CAChooser.Listener {
  private final CAChooser caChooser;
  private final JTextField nicknameField = new JTextField();
  private final JTextField serverNameField = new JTextField();
  private final JPanel panel = new JPanel();

  private final Action createAction = new javax.swing.AbstractAction("Create CA") {

    @Override
    public void actionPerformed(ActionEvent e) {
      createCA();
    }
  };
  private final Action deleteAction = new javax.swing.AbstractAction("Delete CA") {

    @Override
    public void actionPerformed(ActionEvent e) {
      deleteCA();
    }
  };
  private final Action exitAction = new javax.swing.AbstractAction("Exit") {

    @Override
    public void actionPerformed(ActionEvent e) {
      dialog.setVisible(false);
    }
  };


  private CA_Object selectedCA;
  private final Model model;
  private final JDialog dialog;

  /**
   * @param model
   * @param ca
   * @param newCA
   */
  public CAEditor(Model model, CA_Object ca, Component c) {
    this.model = model;
    caChooser = new CAChooser(model, ca);
    JPanel createFields = createNewCAFields();
    JPanel buttons = new JPanel();
    buttons.add(new JButton(createAction));
    buttons.add(new JButton(deleteAction));
    buttons.add(new JButton(exitAction));
    DocumentListener textDocumentListener = new DocumentListener() {

      @Override
      public void insertUpdate(DocumentEvent e) {
        updateButtonEnables();
      }

      @Override
      public void removeUpdate(DocumentEvent e) {
        updateButtonEnables();
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
        updateButtonEnables();
      }
    };
    nicknameField.getDocument().addDocumentListener(textDocumentListener);
    serverNameField.getDocument().addDocumentListener(textDocumentListener);
    nicknameField.addActionListener(createAction);
    serverNameField.addActionListener(createAction);
    caChooser.addListener(this);
    updateButtonEnables();
    dialog = new JDialog(SwingUtilities.getWindowAncestor(c), "CA Editor");
    dialog.setLocationRelativeTo(c);
    dialog.setModalityType(ModalityType.APPLICATION_MODAL);
    Box box = Box.createVerticalBox();
    box.add(caChooser.getComponent());
    box.add(createFields);
    dialog.add(box);
    dialog.add(buttons, BorderLayout.SOUTH);
    dialog.pack();
  }

  /**
   * @param c
   */
  public CA_Object showDialog() {
    dialog.setVisible(true);
    dialog.dispose();
    return selectedCA;
  }

  /**
   * 
   */
  protected void deleteCA() {
    int descendentCount = countDescendents(selectedCA);
    Collection<AbstractAction> actions = new HashSet<AbstractAction>();
    addDescendentActions(selectedCA, actions);
    int actionCount = actions.size();
    Object[] msg = {
        selectedCA.getCommonName() + " has " + (descendentCount == 0 ? "no" : String.valueOf(descendentCount)) + " descendent" + (descendentCount == 1 ? "" : "s"),
        "and",
        selectedCA.getCommonName() + " and descendents are referenced by " + (actionCount == 0 ? "no" : String.valueOf(actionCount)) + " action" + (actionCount == 1 ? "" : "s"),
        "Are you sure you want to delete it and all descendents?"
    };
    int option = JOptionPane.showConfirmDialog(dialog, msg, "Confirm CA Deletion", JOptionPane.OK_CANCEL_OPTION);
    if (option == JOptionPane.OK_OPTION) {
      model.removeActions(actions);
      CA_Object parent = selectedCA.getParent();
      parent.removeChild(selectedCA);
      caChooser.update();
      caChooser.selectCA(parent);
    }
  }

  private int countDescendents(CA_Object caObject) {
    int count = 1;
    for (int i = 0, n = caObject.getChildCount(); i < n; i++) {
      count += countDescendents(caObject.getChild(i));
    }
    return count;
  }

  private void addDescendentActions(CA_Object caObject, Collection<AbstractAction> actions) {
    for (AbstractAction modelAction : model.getActions()) {
      if (modelAction.referencesCA(caObject)) {
        actions.add(modelAction);
      }
    }
  }

  protected void createCA() {
    if (selectedCA == null) {
      return;
    }
    String nickname = nicknameField.getText().trim();
    String serverName = serverNameField.getText().trim();
    if (nickname.isEmpty() || serverName.isEmpty()) {
      return;
    }
    boolean breakAway = !serverName.equals(selectedCA.getServerName());
    CA_Object child = new CA_Object(selectedCA, nickname, breakAway ? serverName : null, null);
    selectedCA.addChild(child);
    caChooser.update();
    nicknameField.setText("");
    caChooser.selectCA(child);
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

  private JPanel createNewCAFields() {
    JPanel msg = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridy = 0;
    gbc.gridx = 0;
    msg.add(new JLabel("Nickname: "), gbc);
    gbc.gridy++;
    msg.add(new JLabel("Server Name: "), gbc);
    gbc.gridy = 0;
    gbc.gridx = 1;
    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.weightx = 1f;
    msg.add(nicknameField, gbc);
    gbc.gridy++;
    msg.add(serverNameField, gbc);
    return msg;
  }

  /**
   * @param caObject
   * @return
   */
  private String getServerName(CA_Object caObject) {
    while (!caObject.isBreakAway() && caObject.getParent() != null) {
      caObject = caObject.getParent();
    }
    return caObject.getServerName();
  }

  /**
   * @see javax.swing.event.TreeSelectionListener#valueChanged(javax.swing.event.TreeSelectionEvent)
   */
  @Override
  public void selectionChanged(CA_Object caObject) {
    selectedCA = caObject;
    if (selectedCA != null) {
      serverNameField.setText(selectedCA.getServerName());
    }
    updateButtonEnables();
  }

  private void updateButtonEnables() {
    createAction.setEnabled(selectedCA != null
        && !nicknameField.getText().trim().isEmpty()
        && !serverNameField.getText().trim().isEmpty());
    deleteAction.setEnabled(selectedCA != null && selectedCA.getParent() != null);
  }
}
