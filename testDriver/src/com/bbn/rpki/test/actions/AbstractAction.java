/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.jdom.Element;

import com.bbn.rpki.test.objects.CA_Object;
import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.tasks.Model;

/**
 * Interface and support for all actions
 *
 * @author tomlinso
 */
public abstract class AbstractAction implements XMLConstants {


  enum ActionType {
    allocate,
    allocateROA,
    chooseCacheCheckTask
  }

  public static void createActions(Element root, Model model) {
    ActionContext actionContext = new ActionContext();
    for (Element child : getChildren(root, TAG_ACTION)) {
      assert child.getName().equals(TAG_ACTION);
      String typeName = child.getAttributeValue(ATTR_ACTION_TYPE);
      ActionType type = ActionType.valueOf(typeName);
      AbstractAction action = null;
      switch (type) {
      case allocate:
        action = new AllocateAction(child, model, actionContext);
        break;
      case allocateROA:
        action = new AllocateROAAction(child, model, actionContext);
        break;
      case chooseCacheCheckTask:
        action = new ChooseCacheCheckTask(child, model, actionContext);
        break;
      }
      if (action != null) {
        model.addAction(action);
      }
    }
    model.initializeActions();
  }

  static List<Element> getChildren(Element element, String tag) {
    return element.getChildren(tag);
  }

  protected final Model model;

  protected AbstractAction(Model model) {
    this.model = model;
  }

  protected Element createElement(ActionType actionType) {
    Element element = new Element(TAG_ACTION);
    element.setAttribute(ATTR_ACTION_TYPE, actionType.name());
    return element;
  }

  public abstract List<String> getInvalidReasons();

  /**
   * @return attributes map
   */
  public abstract Map<String, Object> getAttributes();

  /**
   * Encode this object as XML
   * @param actionContext Provides context for linking together cross references
   * @return an Element representing this AbstractAction
   */
  public abstract Element toXML(ActionContext actionContext);

  /**
   * Get the epochs when something happens in this action.
   * @return the epochs
   */
  public abstract Collection<EpochEvent> getAllEpochEvents();

  /**
   * Get the epochs during which this action should be executed.
   * @return the execution epochs
   */
  public abstract Collection<EpochEvent> getExecutionEpochs();

  /**
   * Perform the action
   * @param executionEpoch TODO
   * @param logger TODO
   */
  public abstract void execute(EpochEvent executionEpoch, TypescriptLogger logger);

  /**
   * @param label
   * @param newValue
   */
  public abstract void updateAttribute(String label, Object newValue);

  /**
   * @return
   */
  public abstract Object getId();

  /**
   * @param epochEvent
   * @return
   */
  public abstract void addExecutionTime(EpochEvent epochEvent, ExecutionTimeContext etContext);

  /**
   * @param caObject
   * @return true if this action references the specified CA_Object
   */
  public abstract boolean referencesCA(CA_Object caObject);

  /**
   * @param ret
   * @param string
   * @return
   */
  protected List<String> appendReason(List<String> ret, String string) {
    if (ret == null) {
      ret = new ArrayList<String>();
    }
    ret.add(string);
    return ret;
  }
}
