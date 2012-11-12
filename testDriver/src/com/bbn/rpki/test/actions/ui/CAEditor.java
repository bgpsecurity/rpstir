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
import java.awt.event.ActionListener;
import java.util.Collection;
import java.util.HashSet;

import javax.swing.Action;
import javax.swing.Box;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;

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

  private final Action newAction = new javax.swing.AbstractAction("New CA") {

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

  private final Action resetAction = new javax.swing.AbstractAction("Reset") {

    @Override
    public void actionPerformed(ActionEvent e) {
      reset();
    }
  };

  private final Action applyAction = new javax.swing.AbstractAction("Apply") {

    @Override
    public void actionPerformed(ActionEvent e) {
      apply();
    }
  };

  private final Action exitAction = new javax.swing.AbstractAction("Exit") {

    @Override
    public void actionPerformed(ActionEvent e) {
      apply();
      dialog.setVisible(false);
    }
  };


  private CA_Object selectedCA;
  private final Model model;
  private final JDialog dialog;

  /**
   * @param model
   * @param ca
   */
  public CAEditor(Model model, CA_Object ca, Component c) {
    this.model = model;
    caChooser = new CAChooser(model, ca);
    JPanel createFields = createNewCAFields();
    JToolBar buttons = new JToolBar();
    buttons.setFloatable(false);
    buttons.add(newAction);
    buttons.add(deleteAction);
    buttons.add(applyAction);
    buttons.add(resetAction);
    buttons.add(exitAction);
    ActionListener l = new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        apply();
      }
    };
    nicknameField.addActionListener(l);
    serverNameField.addActionListener(l);
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
   * Show the dialog and return the last-selected CA
   * @return the last selected CA
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
    String nickname = "Child" + selectedCA.getChildCount();
    CA_Object child = new CA_Object(selectedCA, nickname, null, null);
    selectedCA.addChild(child);
    caChooser.update();
    caChooser.selectCA(child);
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
    reset();
  }

  /**
   * 
   */
  protected void reset() {
    if (selectedCA != null) {
      serverNameField.setText(selectedCA.getServerName());
      nicknameField.setText(selectedCA.getNickname());
    }
    updateButtonEnables();
  }

  private void updateButtonEnables() {
    exitAction.setEnabled(selectedCA == null ||
        (!nicknameField.getText().trim().isEmpty() && !serverNameField.getText().trim().isEmpty()));
    newAction.setEnabled(selectedCA != null);
    deleteAction.setEnabled(selectedCA != null && selectedCA.getParent() != null);
  }

  protected void apply() {
    if (selectedCA != null) {
      CA_Object child = selectedCA;
      selectedCA.setNickname(nicknameField.getText().trim());
      selectedCA.setServerName(serverNameField.getText().trim());
      caChooser.update();
      caChooser.selectCA(child);
    }
  }
}
