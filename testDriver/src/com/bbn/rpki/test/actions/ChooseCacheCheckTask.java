/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.actions;

import java.util.Collection;
import java.util.Collections;
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

  /**
   * 
   */
  private static final String TAG_EPOCH = "epoch";

  enum AttributeType {
    TASK_PATH("Task Path"),
    ID("Id"),
    EPOCH("Epoch");

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

  private static int nextId = 0;

  /**
   * @return
   */
  private static String nextId() {
    nextId ++;
    return String.valueOf(nextId);
  }

  private TaskPath path;
  private final Model model;
  private String id;
  private final EpochEvent epoch;

  /**
   * @param model
   * @param path
   */
  public ChooseCacheCheckTask(Model model, String path) {
    this.model = model;
    this.path = new TaskPath(path);
    this.id = nextId();
    epoch = new EpochEvent(this, "Cache Check ");
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
   * @param actionContext
   */
  public ChooseCacheCheckTask(Model model, Element element, ActionContext actionContext) {
    this.model = model;
    this.path = new TaskPath(element.getAttributeValue(ATTR_PATH));
    this.id = nextId();
    Element epochElement = element.getChild(TAG_EPOCH);
    epoch = new EpochEvent(this, "Cache Check ", epochElement, actionContext);

  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#toXML(ActionContext)
   */
  @Override
  public Element toXML(ActionContext actionContext) {
    Element element = createElement(VALUE_CHOOSE_CACHE_CHECK_TASK);
    element.setAttribute(ATTR_PATH, path.toString());
    element.addContent(epoch.toXML(TAG_EPOCH, actionContext));
    return element;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getAllEpochEvents()
   */
  @Override
  public Collection<EpochEvent> getAllEpochEvents() {
    return Collections.singleton(epoch);
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#execute(EpochEvent, com.bbn.rpki.test.objects.TypescriptLogger)
   */
  @Override
  public void execute(EpochEvent executionEpoch, TypescriptLogger logger) {
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
    ret.put(AttributeType.ID.getDisplayName(), id);
    ret.put(AttributeType.EPOCH.getDisplayName(), epoch);
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
    case ID:
      id = (String) newValue;
      break;
    }
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getId()
   */
  @Override
  public
  String getId() {
    return id;
  }

  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    String[] pathArray = path.getPath();
    String lastTask = pathArray[pathArray.length - 1];
    return String.format("Check Cache after %s", lastTask);
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#getExecutionEpochs()
   */
  @Override
  public Collection<EpochEvent> getExecutionEpochs() {
    return Collections.singleton(epoch);
  }
}
