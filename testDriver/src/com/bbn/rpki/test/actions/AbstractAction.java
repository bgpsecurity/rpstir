/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Collection;
import java.util.LinkedHashMap;

import org.jdom.Element;

import com.bbn.rpki.test.objects.TypescriptLogger;

/**
 * Interface and support for all actions
 *
 * @author tomlinso
 */
public abstract class AbstractAction implements XMLConstants {


  enum ActionType {
    allocate,
  }

  protected Element createElement(String actionType) {
    Element element = new Element(TAG_ACTION);
    element.setAttribute(ATTR_ACTION_TYPE, actionType);
    return element;
  }

  /**
   * @return attributes map
   */
  public abstract LinkedHashMap<String, Object> getAttributes();

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
  public abstract String getId();
}
