/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jdom.Element;

import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.TaskBreakdown;
import com.bbn.rpki.test.tasks.TaskFactory;
import com.bbn.rpki.test.tasks.TaskPath;

/**
 * Select a specified Task for testing.
 * 
 * Follows the path down from the current tasks to a particular task and marks
 * that task as being a task after which cache testing should be performed.
 * The path is specified as an alternation of task names and breakdown names.
 * The first element selects a top task, the second element selects a particular
 * breakdown of that task, the third selects a particular task within that
 * breakdown, etc.
 *
 * @author tomlinso
 */
public class ChooseCacheCheckTask extends AbstractAction {

  enum AttributeType {
    TASK_PATH("Task Path");

    static Map<String, AttributeType> d2o = null;

    static AttributeType forDisplayName(String displayName) {
      if (d2o == null) {
        d2o = new HashMap<String, AttributeType>();
        for (AttributeType at : values()) {
          d2o.put(at.getDisplayName(), at);
        }
      }
      return d2o.get(displayName);
    }

    private String displayName;
    AttributeType(String displayName) {
      this.displayName = displayName;
    }
    public String getDisplayName() {
      return displayName;
    }
  }

  private TaskPath path;
  private final Model model;

  /**
   * @param model
   * @param path
   */
  public ChooseCacheCheckTask(Model model, String path) {
    this.model = model;
    this.path = new TaskPath(path);
  }

  /**
   * @param model
   */
  public ChooseCacheCheckTask(Model model) {
    this(model, "");
  }

  /**
   * @param model
   * @param element
   */
  public ChooseCacheCheckTask(Model model, Element element) {
    this(model, element.getAttributeValue(ATTR_PATH));
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#toXML()
   */
  @Override
  public Element toXML() {
    Element element = createElement(VALUE_CHOOSE_CACHE_CHECK_TASK);
    element.setAttribute(ATTR_PATH, path.toString());
    return element;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#execute(com.bbn.rpki.test.objects.TypescriptLogger)
   */
  @Override
  public void execute(TypescriptLogger logger) {
    // Navigate to the Task
    String[] path = this.path.getPath();
    TaskFactory.Task task = model.getTask(path[0]);
    TaskBreakdown breakdown = null;
    for (int i = 1; i < path.length; i++) {
      if (i % 2 == 0) {
        TaskFactory.Task nTask = breakdown.getTask(path[i]);
        assert nTask != null;
        task = nTask;
      } else {
        breakdown = task.selectTaskBreakdown(path[i]);
        assert breakdown != null;
      }
    }
    task.setTestEnabled(true);
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getAttributes()
   */
  @Override
  public LinkedHashMap<String, Object> getAttributes() {
    LinkedHashMap<String, Object> ret = new LinkedHashMap<String, Object>();
    ret.put(AttributeType.TASK_PATH.getDisplayName(), path);
    return ret;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#updateAttribute(java.lang.String, java.lang.Object)
   */
  @Override
  public void updateAttribute(String label, Object newValue) {
    AttributeType at = AttributeType.forDisplayName(label);
    switch (at) {
    case TASK_PATH:
      path = (TaskPath) newValue;
      break;
    }
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return String.format("Check Cache after %s", path);
  }
}
