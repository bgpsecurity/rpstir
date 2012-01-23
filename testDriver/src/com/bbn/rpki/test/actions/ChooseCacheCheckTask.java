/*
 * Created on Jan 19, 2012
 */
package com.bbn.rpki.test.actions;

import org.jdom.Element;

import com.bbn.rpki.test.objects.TypescriptLogger;
import com.bbn.rpki.test.tasks.Model;
import com.bbn.rpki.test.tasks.Task;
import com.bbn.rpki.test.tasks.TaskBreakdown;

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

  private final String[] path;
  private final Model model;

  /**
   * @param model
   * @param path
   */
  public ChooseCacheCheckTask(Model model, String path) {
    this.model = model;
    this.path = path.split(":");
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
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < path.length; i++) {
      if (i > 0) {
        sb.append(":");
      }
      sb.append(path[i]);
    }
    element.setAttribute(ATTR_PATH, sb.toString());
    return element;
  }

  /**
   * @see com.bbn.rpki.test.actions.AbstractAction#execute(com.bbn.rpki.test.objects.TypescriptLogger)
   */
  @Override
  public void execute(TypescriptLogger logger) {
    // Navigate to the Task
    Task task = model.getTask(path[0]);
    TaskBreakdown breakdown = null;
    for (int i = 1; i < path.length; i++) {
      if (i % 2 == 0) {
        Task nTask = breakdown.getTask(path[i]);
        assert nTask != null;
        task = nTask;
      } else {
        breakdown = task.selectTaskBreakdown(path[i]);
        assert breakdown != null;
      }
    }
    task.setTestEnabled(true);
  }
}
