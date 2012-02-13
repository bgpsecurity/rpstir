/*
 * Created on Jan 12, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import org.jdom.Element;

import com.bbn.rpki.test.objects.TypescriptLogger;

/**
 * Container for the actions of an epoch
 *
 * @author tomlinso
 */
public class EpochActions extends AbstractAction {
  private int epochIndex;
  private final List<AbstractAction> actions;

  /**
   * @param element
   */
  public EpochActions(Element element) {
    String epochIndexString = element.getAttributeValue(ATTR_EPOCH_INDEX);
    epochIndex = Integer.parseInt(epochIndexString);
    @SuppressWarnings("unchecked")
    List<Element> actionElements = element.getChildren(TAG_ACTION);
    actions = new ArrayList<AbstractAction>(actionElements.size());
    for (Element actionElement : actionElements) {
      ActionType actionType = ActionType.valueOf(actionElement.getAttributeValue(ATTR_ACTION_TYPE));
      AbstractAction action = null;
      switch (actionType) {
      case allocate:
        action = new AllocateAction(actionElement);
        break;
      case deallocate:
        action = new DeallocateAction(actionElement);
        break;
      }
      assert action != null;
      addAction(action);
    }
  }

  /**
   * @param i
   * @param actionArray actions to add
   */
  public EpochActions(int i, AbstractAction...actionArray) {
    this.epochIndex = i;
    this.actions = new ArrayList<AbstractAction>(Arrays.asList(actionArray));
  }

  /**
   * @param action
   */
  private void addAction(AbstractAction action) {
    actions.add(action);
  }

  /**
   * Add an action at a specific index
   * @param index
   * @param action
   */
  public void addAction(int index, AbstractAction action) {
    actions.add(index, action);
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#toXML()
   */
  @Override
  public Element toXML() {
    Element element = new Element(TAG_EPOCH);
    element.setAttribute(ATTR_EPOCH_INDEX, String.valueOf(epochIndex));
    for (AbstractAction action : actions) {
      Element actionElement = action.toXML();
      element.addContent(actionElement);
    }
    return element;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#execute(TypescriptLogger)
   */
  @Override
  public void execute(TypescriptLogger logger) {
    if (logger != null) {
      logger.format("Executing %d action%s%n", actions.size(), actions.size() != 1 ? "s" : "");
    }
    for (AbstractAction action : actions) {
      action.execute(logger);
    }
  }

  /**
   * @param index
   * @return the action at the specified index
   */
  public Object getAction(int index) {
    return actions.get(index);
  }

  /**
   * @return the cound of actions in the epoch
   */
  public int getActionCount() {
    return actions.size();
  }

  /**
   * @param child
   * @return the index of the specified action
   */
  public int indexOf(Object child) {
    return actions.indexOf(child);
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getAttributes()
   */
  @Override
  public LinkedHashMap<String, Object> getAttributes() {
    // Not editable
    return null;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#updateAttribute(java.lang.String, java.lang.Object)
   */
  @Override
  public void updateAttribute(String label, Object newValue) {
    // Not editable
  }

  /**
   * @return the epoch index
   */
  public int getEpochIndex() {
    return epochIndex;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return "Actions of Epoch " + epochIndex;
  }

  /**
   * @param index
   */
  public void removeAction(int index) {
    actions.remove(index);
  }

  /**
   * @param index
   */
  public void setEpochIndex(int index) {
    this.epochIndex = index;
  }
}
