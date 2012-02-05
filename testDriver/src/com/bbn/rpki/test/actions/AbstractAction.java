/*
 * Created on Jan 11, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.LinkedHashMap;

import org.jdom.Element;

import com.bbn.rpki.test.objects.TypescriptLogger;

/**
 * Interface and support for all actions
 *
 * @author tomlinso
 */
public abstract class AbstractAction {

  protected static final String TAG_ACTION = "action";

  protected static final String TAG_EPOCH = "epoch";

  protected static final String ATTR_TYPE = "type";

  protected static final String ATTR_ALLOCATION_ID = "allocationId";

  protected static final String ATTR_ALLOCATION_INDEX = "allocationIndex";

  protected static final String ATTR_PARENT_NAME = "parentName";

  protected static final String ATTR_CHILD_NAME = "childName";

  protected static final String ATTR_EPOCH_INDEX = "epoch-index";

  protected static final String ATTR_ACTION_TYPE = "actionType";

  protected static final String ATTR_PATH = "path";
  protected static final String VALUE_ALLOCATE = "allocate";
  protected static final String VALUE_DEALLOCATE = "deallocate";
  protected static final String VALUE_CHOOSE_CACHE_CHECK_TASK = "choose-check-task";

  enum ActionType {
    allocate,
    deallocate,
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
   * @return an Element representing this AbstractAction
   */
  public abstract Element toXML();
  /**
   * Perform the action
   * @param logger TODO
   */
  public abstract void execute(TypescriptLogger logger);

  /**
   * @param label
   * @param newValue
   */
  public abstract void updateAttribute(String label, Object newValue);
}
