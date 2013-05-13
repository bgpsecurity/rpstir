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
import com.bbn.rpki.test.actions.EpochEvent;
import com.bbn.rpki.test.objects.AllocationId;
import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.IPRangeType;
import com.bbn.rpki.test.objects.Pair;
import com.bbn.rpki.test.objects.TypedPair;
import com.bbn.rpki.test.objects.TypedPairList;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskPath;

/**
 * Displays the details of an action.
 * 
 * At the top is a title stating
 * the kind of action and its principal attributes. Below are all the attributes of the
 * action. An editor is provided for each attribute depending on what kind of value the
 * attribute has. Below that is a tabbed pane with a tab for each epochEvent in which the
 * action plays a part. Constraints on the timing of the part of the action can be selected.
 *
 * @author tomlinso
 */
public class ActionDetail {
  private interface Saver {
    void save();
  }

  interface EpochCallback {
    void add(EpochEvent epochEvent);
    void remove(EpochEvent epochEvent);
    /**
     * @param selectedEpochEvent
     * @return true of the selected epochEvent can be removed from the list
     */
    boolean canRemove(EpochEvent selectedEpochEvent);
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
  private final JScrollPane scrollPane =
      new JScrollPane(panel,
                      JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                      JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
  private final Model model;
  private final List<Saver> savers = new ArrayList<Saver>();
  private AbstractAction action;
  private EpochEvent epochEvent;
  private final List<EpochEvent> epochEvents = new ArrayList<EpochEvent>();
  private JTabbedPane epochEventsPane = null;
  private final Action applyAction = new javax.swing.AbstractAction("Apply") {

    @Override
    public void actionPerformed(ActionEvent e) {
      for (Saver saver : savers) {
        saver.save();
      }
      model.epochsChanged();
      setAction(action, epochEvent);
    }
  };

  private final Action resetAction = new javax.swing.AbstractAction("Reset") {

    @Override
    public void actionPerformed(ActionEvent e) {
      setAction(action, epochEvent);
    }
  };
  /**
   * @param model
   */
  public ActionDetail(Model model) {
    this.model = model;
    JPanel buttons = new JPanel();
    buttons.add(new JButton(applyAction));
    buttons.add(new JButton(resetAction));
    Font titleFont = title.getFont().deriveFont(20f);
    title.setFont(titleFont);
    outerPanel.add(title, BorderLayout.NORTH);
    outerPanel.add(buttons, BorderLayout.SOUTH);
    outerPanel.add(scrollPane, BorderLayout.CENTER);
  }

  /**
   * @param action
   * @param epochEvent
   */
  public void setAction(final AbstractAction action, EpochEvent epochEvent) {
    if (action != this.action && !checkValidity()) {
      return;
    }
    this.epochEvent = epochEvent;
    this.epochEvents.clear();
    panel.removeAll();
    epochEventsPane = null;
    savers.clear();
    this.action = action;
    String titleText = action == null ? "No Action Selected" : action.toString();
    title.setText(titleText);
    title.setToolTipText(titleText);
    if (action != null) {
      this.epochEvents.addAll(action.getAllEpochEvents());
      GridBagConstraints gbc = new GridBagConstraints();
      gbc.gridy = 0;
      gbc.insets = new Insets(3, 5, 3, 5);
      final Map<String, Object> attrs = action.getAttributes();
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
        if (value instanceof EpochEvent) {
          // Combine EpochEVent components into a tabbed pane
          if (epochEventsPane == null) {
            epochEventsPane = new JTabbedPane();
            gbc.gridx = 0;
            gbc.gridwidth = 2;
            gbc.weightx = 1f;
            gbc.fill = component instanceof JScrollPane ? GridBagConstraints.BOTH : GridBagConstraints.HORIZONTAL;
            gbc.weighty = 0f;
            panel.add(epochEventsPane, gbc);
          }
          epochEventsPane.add(label, component);
          if (value == epochEvent) {
            epochEventsPane.setSelectedComponent(component);
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
      if (epochEventsPane != null) {
        epochEventsPane.getModel().addChangeListener(new ChangeListener() {

          @Override
          public void stateChanged(ChangeEvent e) {
            int index = epochEventsPane.getSelectedIndex();
            if (index < 0) {
              ActionDetail.this.epochEvent = null;
            }
            else {
              ActionDetail.this.epochEvent = epochEvents.get(index);
            }
          }
        });
      }
      panel.add(new JPanel(null), gbc);
    }
    panel.revalidate();
    panel.repaint();
  }

  /**
   * @return
   */
  public boolean checkValidity() {
    return InvalidActionDialog.checkValidity(getComponent(), this.action);
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
    if (value instanceof AllocationId) {
      return getAllocationIdComponent((AllocationId) value, setter);
    }
    if (value instanceof TypedPairList) {
      return getPairListComponent((TypedPairList) value, setter);
    }
    if (value instanceof IPRangeType) {
      return getIPRangeTypeComponent((IPRangeType) value, setter);
    }
    if (value instanceof TypedPair) {
      return getTypedPairComponent((TypedPair) value, setter);
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
    if (value instanceof EpochEvent) {
      return getEpochEventComponent((EpochEvent) value, setter);
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
  private Component getCAComponent(CA_Object ca, final AbstractSetter setter) {
    Box c = Box.createHorizontalBox();
    c.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Color.BLACK), BorderFactory.createEmptyBorder(0, 5, 0, 0)));
    final JLabel nameLabel = new JLabel(ca.getCommonName());
    c.add(nameLabel);
    final JButton editButton = new JButton("Edit");
    final CA_Object[] settableCA = {ca};
    editButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        CAChooser caChooser = new CAChooser(model, settableCA[0]);
        CA_Object newCA = caChooser.showDialog(editButton);
        if (newCA != null) {
          setter.setValue(newCA);
          nameLabel.setText(newCA.getCommonName());
          settableCA[0] = newCA;
        }
      }
    });
    c.add(Box.createHorizontalGlue());
    c.add(editButton);
    return c;
  }

  private Component getAllocationIdComponent(final AllocationId allocationId, final AbstractSetter setter) {
    AbstractFormatter formatter = new AbstractFormatter() {

      @Override
      public Object stringToValue(String text) throws ParseException {
        return AllocationId.get(text);
      }

      @Override
      public String valueToString(Object value) throws ParseException {
        if (value == null) {
          return "null";
        }
        return ((AllocationId) value).toString();
      }
    };
    final JFormattedTextField component = new JFormattedTextField(formatter);
    component.setValue(allocationId);
    registerListener(new Saver() {

      @Override
      public void save() {
        setter.setValue(component.getValue());
      }
    });
    return component;
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
        return ((Pair) value).getPairString();
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

  private Component getIPRangeTypeComponent(IPRangeType value, final AbstractSetter setter) {
    final JComboBox<IPRangeType> box = new JComboBox<IPRangeType>(IPRangeType.values());
    box.setSelectedItem(value);
    registerListener(new Saver() {

      @Override
      public void save() {
        setter.setValue(box.getSelectedItem());
      }
    });
    return box;
  }

  private Component getEpochEventComponent(EpochEvent value, final AbstractSetter setter) {
    Box box = Box.createVerticalBox();
    box.add(getEpochEventsBeforeComponent(value));
    box.add(getEpochEventsCoincidentComponent(value));
    box.add(getEpochEventsAfterComponent(value));
    Collection<EpochEvent> epochEvents = model.getEpochEvents();
    EpochEvent[] epochArray = new EpochEvent[epochEvents.size()];
    epochArray = epochEvents.toArray(epochArray);
    final JComboBox<EpochEvent> combo = new JComboBox<EpochEvent>(epochArray);
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
   * @param epochEvent
   * @return
   */
  private Component getEpochEventsCoincidentComponent(final EpochEvent epochEvent) {
    Collection<EpochEvent> coincident = epochEvent.getCoincidentEpochs();
    Collection<EpochEvent> candidates = model.getPossibleCoincidentEpochs(epochEvent);
    return getEpochsComponent(epochEvent, "Coincident Epoch Events", coincident, candidates, new EpochCallback() {

      @Override
      public void add(EpochEvent epochToAdd) {
        epochEvent.addCoincident(epochToAdd, false);
      }

      @Override
      public void remove(EpochEvent epochToRemove) {
        epochEvent.removeCoincident(epochToRemove);
      }

      @Override
      public boolean canRemove(EpochEvent selectedEpoch) {
        return epochEvent.canRemoveCoincident(selectedEpoch);
      }
    });
  }


  /**
   * @param epochEvent
   * @return
   */
  private Component getEpochEventsBeforeComponent(final EpochEvent epochEvent) {
    Collection<EpochEvent> predecessors = epochEvent.getPredecessorEpochEvents();
    Collection<EpochEvent> candidates = model.getPossiblePredecessors(epochEvent);
    return getEpochsComponent(epochEvent, "Predecessor Epoch Events", predecessors, candidates, new EpochCallback() {

      @Override
      public void add(EpochEvent epochToAdd) {
        epochEvent.addPredecessor(epochToAdd, false);
      }

      @Override
      public void remove(EpochEvent epochToRemove) {
        epochEvent.removePredecessor(epochToRemove);
      }

      @Override
      public boolean canRemove(EpochEvent selectedEpoch) {
        return epochEvent.canRemovePredecessor(selectedEpoch);
      }
    });
  }

  /**
   * @param epochEvent
   * @return
   */
  private Component getEpochEventsAfterComponent(final EpochEvent epochEvent) {
    Collection<EpochEvent> successors = epochEvent.getSuccessorEpochEvents();
    Collection<EpochEvent> candidates = model.getPossibleSuccessors(epochEvent);
    return getEpochsComponent(epochEvent, "Successor Epoch Events", successors, candidates, new EpochCallback() {

      @Override
      public void add(EpochEvent epochToAdd) {
        epochEvent.addSuccessor(epochToAdd, false);
      }

      @Override
      public void remove(EpochEvent epochToRemove) {
        epochEvent.removeSuccessor(epochToRemove);
      }

      @Override
      public boolean canRemove(EpochEvent selectedEpoch) {
        return epochEvent.canRemoveSuccessor(selectedEpoch);
      }
    });
  }

  private Component getEpochsComponent(final EpochEvent epochEvent, String title, final Collection<EpochEvent> currentSelection, Collection<EpochEvent> availableEpochs, final EpochCallback cb) {
    return new EpochsComponent(model, epochEvent, title, currentSelection, availableEpochs, cb);
  }

  private Component getTypedPairComponent(final TypedPair typedPair, final AbstractSetter setter) {
    final JPanel panel = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridy = 0;
    gbc.gridx = 0;
    panel.add(new JLabel("INR Type: "), gbc);
    gbc.gridx = 1;
    AbstractSetter typeSetter = new AbstractSetter() {

      @Override
      void updateAttribute() {
        typedPair.type =(IPRangeType) newValue;
      }
    };
    panel.add(getComponent(typedPair.type, typeSetter), gbc);
    gbc.gridx = 2;
    panel.add(new JLabel("  Range: "), gbc);
    gbc.gridx = 3;
    gbc.fill = GridBagConstraints.HORIZONTAL;
    gbc.weightx = 1f;
    AbstractSetter pairSetter = new AbstractSetter() {
      @Override
      void updateAttribute() {
        Pair pair = (Pair) newValue;
        typedPair.tag = pair.tag;
        typedPair.arg = pair.arg;
      }
    };
    panel.add(getPairComponent(typedPair, pairSetter), gbc);
    return panel;
  }

  private Component getPairListComponent(final TypedPairList list, final AbstractSetter setter) {
    final JPanel listData = new JPanel(new GridBagLayout());
    final GridBagConstraints gbc = new GridBagConstraints();
    gbc.gridy = 0;
    for (int i = 0, n = list.size(); i < n; i++) {
      TypedPair element = list.get(i);
      addTypedPair(setter, list, listData, gbc, element);
    }
    final JButton newButton = new JButton("Add");
    newButton.addActionListener(new ActionListener() {
      @Override
      public void actionPerformed(ActionEvent e) {
        listData.remove(newButton);
        TypedPair newPair = new TypedPair(IPRangeType.ipv4, "p", BigInteger.ZERO);
        list.add(newPair);
        addTypedPair(setter, list, listData, gbc, newPair);
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
  private void addTypedPair(final AbstractSetter setter,
                            final TypedPairList list,
                            final JPanel listData,
                            GridBagConstraints gbc,
                            final TypedPair element) {
    AbstractSetter setter2 = new AbstractSetter() {
      @Override
      public void updateAttribute() {
        int index = list.indexOf(element);
        assert index >= 0;
        list.set(index, (TypedPair) newValue);
        setter.setValue(list);
      }
    };

    final Component component = getComponent(element, setter2);
    addTypedPairComponent(listData, gbc, component);
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
  private void addTypedPairComponent(final JPanel listData, GridBagConstraints gbc,
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
