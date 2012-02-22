/*
 * Created on Feb 2, 2012
 */
package com.bbn.rpki.test.actions.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.Action;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFormattedTextField;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import com.bbn.rpki.test.actions.AbstractAction;
import com.bbn.rpki.test.actions.Epoch;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.PairList;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskPath;

/**
 * Displays the details of an action
 *
 * @author tomlinso
 */
public class ActionDetail {
  private interface Saver {
    void save();
  }

  interface EpochCallback {
    void add(Epoch epoch);
    void remove(Epoch epoch);
    /**
     * @param selectedEpoch
     * @return true of the selected epoch can be removed from the list
     */
    boolean canRemove(Epoch selectedEpoch);
  }

  private abstract class AbstractSetter {
    protected Object newValue;

    void setValue(Object newValue) {
      this.newValue = newValue;
      updateAttribute();
    }

    abstract void updateAttribute();
  }

  private final JPanel outerPanel = new JPanel(new BorderLayout());
  private final JLabel title = new JLabel();
  private final JPanel panel = new JPanel(new GridBagLayout());
  private final Model model;
  private final List<Saver> savers = new ArrayList<Saver>();
  private AbstractAction action;
  private Epoch epoch;
  private final List<Epoch> epochs = new ArrayList<Epoch>();
  private JTabbedPane epochsPane = null;
  private final Action saveAction = new javax.swing.AbstractAction("Save") {

    @Override
    public void actionPerformed(ActionEvent e) {
      for (Saver saver : savers) {
        saver.save();
      }
      setAction(action, epoch);
    }
  };

  private final Action resetAction = new javax.swing.AbstractAction("Reset") {

    @Override
    public void actionPerformed(ActionEvent e) {
      setAction(action, epoch);
    }
  };
  /**
   * @param model
   */
  public ActionDetail(Model model) {
    this.model = model;
    JPanel buttons = new JPanel();
    buttons.add(new JButton(saveAction));
    buttons.add(new JButton(resetAction));
    Font titleFont = title.getFont().deriveFont(20f);
    title.setFont(titleFont);
    outerPanel.add(title, BorderLayout.NORTH);
    outerPanel.add(buttons, BorderLayout.SOUTH);
    outerPanel.add(panel, BorderLayout.CENTER);
  }

  /**
   * @param action
   * @param epoch
   */
  public void setAction(final AbstractAction action, Epoch epoch) {
    this.action = action;
    this.epoch = epoch;
    this.epochs.clear();
    panel.removeAll();
    epochsPane = null;
    savers.clear();
    title.setText(action == null ? "No Action Selected" : action.toString());
    if (action != null) {
      GridBagConstraints gbc = new GridBagConstraints();
      gbc.gridy = 0;
      gbc.insets = new Insets(3, 5, 3, 5);
      final LinkedHashMap<String, Object> attrs = action.getAttributes();
      for (Map.Entry<String, Object> entry : attrs.entrySet()) {
        final String label = entry.getKey();
        Object value = entry.getValue();
        AbstractSetter setter = new AbstractSetter() {

          @Override
          public void updateAttribute() {
            attrs.put(label, newValue);
            action.updateAttribute(label, newValue);
          }
        };
        Component component = getComponent(value, setter);
        if (value instanceof Epoch) {
          // Combine Epoch components into a tabbed pane
          if (epochsPane == null) {
            epochsPane = new JTabbedPane();
            gbc.gridx = 0;
            gbc.gridwidth = 2;
            gbc.weightx = 1f;
            gbc.fill = component instanceof JScrollPane ? GridBagConstraints.BOTH : GridBagConstraints.HORIZONTAL;
            gbc.weighty = 0f;
            panel.add(epochsPane, gbc);
          }
          epochsPane.add(label, component);
          if (value == epoch) {
            epochsPane.setSelectedComponent(component);
          }
        } else {
          gbc.gridx = 0;
          gbc.gridwidth = 1;
          gbc.fill = GridBagConstraints.NONE;
          gbc.weightx = 0f;
          gbc.weighty = 0f;
          gbc.anchor = GridBagConstraints.NORTHWEST;
          panel.add(new JLabel(label), gbc);
          gbc.gridx = 1;
          gbc.weightx = 1f;
          gbc.fill = component instanceof JScrollPane ? GridBagConstraints.BOTH : GridBagConstraints.HORIZONTAL;
          gbc.weighty = 0f;
          panel.add(component, gbc);
        }
        gbc.gridy++;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1f;
      }
      gbc.gridx = 0;
      gbc.gridwidth = 2;
      gbc.weighty = 1f;
      if (epochsPane != null) {
        epochsPane.getModel().addChangeListener(new ChangeListener() {

          @Override
          public void stateChanged(ChangeEvent e) {
            int index = epochsPane.getSelectedIndex();
            if (index < 0) {
              ActionDetail.this.epoch = null;
            }
            else {
              ActionDetail.this.epoch = epochs.get(index);
            }
          }
        });
      }
      panel.add(new JPanel(null), gbc);
    }
    panel.revalidate();
    panel.repaint();
  }

  private void registerListener(Saver saver) {
    savers.add(saver);
  }

  private Component getComponent(Object value, final AbstractSetter setter) {
    if (value instanceof Number) {
      return getNumberComponent(value, setter);
    }
    if (value instanceof String) {
      return getStringComponent(value, setter);
    }
    if (value instanceof PairList) {
      return getPairListComponent((PairList) value, setter);
    }
    if (value instanceof IPRangeType) {
      return getIPRangeTypeComponent(value, setter);
    }
    if (value instanceof Pair) {
      return getPairComponent((Pair) value, setter);
    }
    if (value instanceof CA_Object) {
      return getCAComponent((CA_Object) value, setter);
    }
    if (value instanceof TaskPath) {
      return getTaskPathComponent((TaskPath) value, setter);
    }
    if (value instanceof Epoch) {
      return getEpochComponent((Epoch) value, setter);
    }
    assert false;
    return null;
  }

  private Component getTaskPathComponent(final TaskPath taskPath, final AbstractSetter setter) {
    final TaskPathEditor tpe = new TaskPathEditor(model);
    tpe.addActionListener(new ActionListener() {

      @Override
      public void actionPerformed(ActionEvent e) {
        TaskPath newTaskPath = tpe.getTaskPath();
        if (newTaskPath != null) {
          setter.setValue(newTaskPath);
        }
      }
    });
    tpe.setTaskPath(taskPath);
    return tpe.getComponent();
  }

  /**
   * @param value
   * @param setter
   * @return
   */
  private Component getCAComponent(final CA_Object ca, final AbstractSetter setter) {
    Box c = Box.createHorizontalBox();
    c.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Color.BLACK), BorderFactory.createEmptyBorder(0, 5, 0, 0)));
    final JLabel nameLabel = new JLabel(ca.getCommonName());
    c.add(nameLabel);
    final JButton editButton = new JButton("Edit");
    editButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        CAChooser caChooser = new CAChooser(model, ca);
        CA_Object newCA = caChooser.showDialog(editButton);
        if (newCA != null) {
          setter.setValue(newCA);
          nameLabel.setText(newCA.getCommonName());
        }
      }
    });
    c.add(Box.createHorizontalGlue());
    c.add(editButton);
    return c;
  }

  /**
   * @param value
   * @param setter
   * @return
   */
  private Component getPairComponent(final Pair pair, final AbstractSetter setter) {
    AbstractFormatter formatter = new AbstractFormatter() {

      @Override
      public Object stringToValue(String text) throws ParseException {
        String[] p = text.split("%");
        int n = p.length;
        if (n != 2) {
          throw new ParseException("", 0);
        }
        BigInteger bi = new BigInteger(p[1]);
        pair.arg = bi;
        pair.tag = p[0];
        return pair;
      }

      @Override
      public String valueToString(Object value) throws ParseException {
        if (value == null) {
          return "null";
        }
        return value.toString();
      }
    };
    final JFormattedTextField component = new JFormattedTextField(formatter);
    component.setValue(pair);
    registerListener(new Saver() {

      @Override
      public void save() {
        setter.setValue(component.getValue());
      }
    });
    return component;
  }

  private Component getIPRangeTypeComponent(Object value, final AbstractSetter setter) {
    final JComboBox box = new JComboBox(IPRangeType.values());
    box.setSelectedItem(value);
    registerListener(new Saver() {

      @Override
      public void save() {
        setter.setValue(box.getSelectedItem());
      }
    });
    return box;
  }

  private Component getEpochComponent(Epoch value, final AbstractSetter setter) {
    Box box = Box.createVerticalBox();
    box.add(getEpochsBeforeComponent(value));
    box.add(getEpochsCoincidentComponent(value));
    box.add(getEpochsAfterComponent(value));
    Collection<Epoch> epochs = model.getEpochs();
    Epoch[] epochArray = new Epoch[epochs.size()];
    epochArray = epochs.toArray(epochArray);
    final JComboBox combo = new JComboBox(epochArray);
    combo.setSelectedItem(value);
    registerListener(new Saver() {

      @Override
      public void save() {
        setter.setValue(combo.getSelectedItem());
      }
    });
    return box;
  }

  /**
   * @param epoch
   * @return
   */
  private Component getEpochsCoincidentComponent(final Epoch epoch) {
    Collection<Epoch> coincident = epoch.getCoincidentEpochs();
    Collection<Epoch> candidates = model.getPossibleCoincidentEpochs(epoch);
    return getEpochsComponent(epoch, "Coincident Epochs", coincident, candidates, new EpochCallback() {

      @Override
      public void add(Epoch epochToAdd) {
        epoch.addCoincident(epochToAdd, false);
      }

      @Override
      public void remove(Epoch epochToRemove) {
        epoch.removeCoincident(epochToRemove);
      }

      @Override
      public boolean canRemove(Epoch selectedEpoch) {
        return epoch.canRemoveCoincident(selectedEpoch);
      }
    });
  }


  /**
   * @param epoch
   * @return
   */
  private Component getEpochsBeforeComponent(final Epoch epoch) {
    Collection<Epoch> predecessors = epoch.getPredecessorEpochs();
    Collection<Epoch> candidates = model.getPossiblePredecessors(epoch);
    return getEpochsComponent(epoch, "Predecessor Epochs", predecessors, candidates, new EpochCallback() {

      @Override
      public void add(Epoch epochToAdd) {
        epoch.addPredecessor(epochToAdd, false);
      }

      @Override
      public void remove(Epoch epochToRemove) {
        epoch.removePredecessor(epochToRemove);
      }

      @Override
      public boolean canRemove(Epoch selectedEpoch) {
        return epoch.canRemovePredecessor(selectedEpoch);
      }
    });
  }

  /**
   * @param epoch
   * @return
   */
  private Component getEpochsAfterComponent(final Epoch epoch) {
    Collection<Epoch> successors = epoch.getSuccessorEpochs();
    Collection<Epoch> candidates = model.getPossibleSuccessors(epoch);
    return getEpochsComponent(epoch, "Successor Epochs", successors, candidates, new EpochCallback() {

      @Override
      public void add(Epoch epochToAdd) {
        epoch.addSuccessor(epochToAdd, false);
      }

      @Override
      public void remove(Epoch epochToRemove) {
        epoch.removeSuccessor(epochToRemove);
      }

      @Override
      public boolean canRemove(Epoch selectedEpoch) {
        return epoch.canRemoveSuccessor(selectedEpoch);
      }
    });
  }

  private Component getEpochsComponent(final Epoch epoch, String title, final Collection<Epoch> currentSelection, Collection<Epoch> availableEpochs, final EpochCallback cb) {
    return new EpochsComponent(model, epoch, title, currentSelection, availableEpochs, cb);
  }


  private Component getPairListComponent(final PairList list, final AbstractSetter setter) {
    final JPanel listData = new JPanel(new GridBagLayout());
    final GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridy = 0;
    for (int i = 0, n = list.size(); i < n; i++) {
      Pair element = list.get(i);
      addPair(setter, list, listData, gbc, element);
    }
    final JButton newButton = new JButton("Add");
    newButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        listData.remove(newButton);
        Pair newPair = new Pair("p", BigInteger.ZERO);
        list.add(newPair);
        addPair(setter, list, listData, gbc, newPair);
        addPairButton(listData, gbc, newButton);
        listData.revalidate();
        listData.repaint();
      }
    });
    addPairButton(listData, gbc, newButton);
    return listData;
  }

  /**
   * @param value
   * @param setter
   * @return
   */
  private Component getStringComponent(Object value, final AbstractSetter setter) {
    final JTextField component = new JTextField((String) value);
    registerListener(new Saver() {

      @Override
      public void save() {
        setter.setValue(component.getText());
      }
    });
    return component;
  }

  /**
   * @param value
   * @param setter
   * @return
   */
  private Component getNumberComponent(Object value, final AbstractSetter setter) {
    final JFormattedTextField component = new JFormattedTextField(value);
    registerListener(new Saver() {

      @Override
      public void save() {
        setter.setValue(component.getValue());
      }
    });
    return component;
  }

  /**
   * @param setter
   * @param list
   * @param listData
   * @param gbc
   * @param editedList
   * @param index
   * @param element
   */
  private void addPair(final AbstractSetter setter,
                       final PairList list,
                       final JPanel listData,
                       GridBagConstraints gbc,
                       final Pair element) {
    AbstractSetter setter2 = new AbstractSetter() {
      @Override
      public void updateAttribute() {
        int index = list.indexOf(element);
        assert index >= 0;
        list.set(index, (Pair) newValue);
        setter.setValue(list);
      }
    };

    final Component component = getComponent(element, setter2);
    addPairComponent(listData, gbc, component);
    final JButton deleteButton = new JButton("Delete");
    deleteButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        list.remove(element);
        listData.remove(component);
        listData.remove(deleteButton);
        listData.revalidate();
        listData.repaint();
      }
    });
    addPairButton(listData, gbc, deleteButton);
    gbc.gridy++;
  }

  /**
   * @param listData
   * @param gbc
   * @param component
   */
  private void addPairComponent(final JPanel listData, GridBagConstraints gbc,
                                final Component component) {
    gbc.gridx = 0;
    gbc.fill = GridBagConstraints.BOTH;
    gbc.weightx = 1f;
    listData.add(component, gbc);
  }

  /**
   * @param listData
   * @param gbc
   * @param deleteButton
   */
  private void addPairButton(final JPanel listData, GridBagConstraints gbc,
                             final JButton deleteButton) {
    gbc.gridx = 1;
    gbc.fill = GridBagConstraints.NONE;
    gbc.weightx = 0f;
    listData.add(deleteButton, gbc);
  }

  /**
   * @return the panel component
   */
  public Component getComponent() {
    return outerPanel;
  }
}
