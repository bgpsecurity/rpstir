/*
 * Created on Feb 21, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Collection;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import com.bbn.rpki.test.actions.EpochEvent;
import com.bbn.rpki.test.actions.ui.ActionDetail.EpochCallback;
import com.bbn.rpki.test.tasks.Model;

class EpochsComponent extends JPanel {
  final DefaultListModel<EpochEvent> listModel = new DefaultListModel<EpochEvent>();
  final JList<EpochEvent> list = new JList<EpochEvent>(listModel);
  final JButton removeButton = new JButton("Remove");
  final JButton addButton = new JButton("Add...");
  private final Collection<EpochEvent> currentSelection;
  private EpochCallback cb;
  private Collection<EpochEvent> availableEpochs;
  private Model model;

  EpochsComponent(Model model, final EpochEvent epoch, final String title, final Collection<EpochEvent> currentSelection, Collection<EpochEvent> availableEpochs, final ActionDetail.EpochCallback cb) {
    super(new BorderLayout());
    this.model = model;
    this.cb = cb;
    this.currentSelection = currentSelection;
    if (currentSelection.isEmpty()) {
      markEmptyList(title);
    } else {
      for (EpochEvent coincidentEpoch : currentSelection) {
        listModel.addElement(coincidentEpoch);
      }
    }
    setBorder(BorderFactory.createEtchedBorder());
    list.setBorder(BorderFactory.createEtchedBorder());
    add(list);
    JPanel buttons = new JPanel();
    removeButton.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        for (EpochEvent epochEventToRemove : list.getSelectedValuesList()) {
          cb.remove(epochEventToRemove);
          listModel.removeElement(epochEventToRemove);
          currentSelection.remove(epochEventToRemove);
          EpochsComponent.this.model.epochsChanged();
          if (currentSelection.isEmpty()) {
            markEmptyList(title);
          }
        }
      }
    });
    this.availableEpochs = availableEpochs;
    addButton.setEnabled(!availableEpochs.isEmpty());
    addButton.setToolTipText(availableEpochs.isEmpty() ? "No epochs available" : "Add epoch from list");
    addButton.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        addEpoch();
      }
    });
    enableRemove(false);
    buttons.add(removeButton);
    buttons.add(addButton);
    list.addListSelectionListener(new ListSelectionListener() {
      @Override
      public void valueChanged(ListSelectionEvent e) {
        if (currentSelection.isEmpty()) {
          // Not a real selection -- ignore
          return;
        }
        List<EpochEvent> selection = list.getSelectedValuesList();
        boolean canRemove = selection.size() > 0;
        for (EpochEvent selectedEpoch : selection) {
          if (!cb.canRemove(selectedEpoch)) {
            canRemove = false;
            break;
          }
        }
        enableRemove(canRemove);
      }});
    add(buttons, BorderLayout.SOUTH);
    JLabel titleLabel = new JLabel(title);
    titleLabel.setFont(titleLabel.getFont().deriveFont(16f));
    add(titleLabel, BorderLayout.NORTH);
  }

  /**
   * @param b
   */
  public void enableRemove(boolean b) {
    removeButton.setEnabled(b);
    removeButton.setToolTipText(b ? "Remove the selected epoch" : "No epoch selected");
  }

  /**
   * @param title
   */
  public void markEmptyList(String title) {
    listModel.addElement(new EpochEvent(null, "<No " + title + ">"));
  }

  void addEpoch() {
    EpochEvent[] epochArray = new EpochEvent[availableEpochs.size()];
    epochArray = availableEpochs.toArray(epochArray);
    JComboBox<EpochEvent> msg = new JComboBox<EpochEvent>(epochArray);
    int option = JOptionPane.showConfirmDialog(this, msg, "Select Epoch", JOptionPane.OK_CANCEL_OPTION);
    if (option == JOptionPane.OK_OPTION) {
      if (currentSelection.isEmpty()) {
        listModel.removeAllElements();
      }
      EpochEvent selectedEpochEvent = epochArray[msg.getSelectedIndex()];
      cb.add(selectedEpochEvent);
      currentSelection.add(selectedEpochEvent);
      listModel.addElement(selectedEpochEvent);
      // Notify the main model that this epoch has different constraints
      // The ActionTree will be notified in turn.
      model.epochsChanged();
    }
  }
}