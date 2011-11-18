/*
 * Created on Oct 29, 2011
 */
package com.bbn.rpki.test.model;

import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;

import org.jdom.Element;

/**
 * Contains all the tasks, tests, etc.
 *
 * @author RTomlinson
 */
public class TestModel extends XMLBase {
  private static final String TAG_TASK_DESCRIPTION = "task-description";
  private final Map<String, TaskDescription> taskDescriptions = new TreeMap<String, TaskDescription>();
  private boolean modified;
  
  /**
   * @return the modified
   */
  public boolean isModified() {
    return modified;
  }

  /**
   * @param modified the modified to set
   */
  public void setModified(boolean modified) {
    this.modified = modified;
  }

  /**
   * Default constructor
   */
  public TestModel() {
  }
  
  /**
   * @param element
   */
  public TestModel(Element element) {
    for (Element taskDescriptionElement : getChildren(element, TAG_TASK_DESCRIPTION)) {
      TaskDescription taskDescription = new TaskDescription(taskDescriptionElement);
      taskDescriptions.put(taskDescription.getName(), taskDescription);
    }
    setModified(false);
  }
  
  /**
   * @param element
   */
  public void toXML(Element element) {
    for (TaskDescription taskDescription : taskDescriptions.values()) {
      Element taskDescriptionElement = new Element(TAG_TASK_DESCRIPTION);
      taskDescription.toXML(taskDescriptionElement);
      element.addContent(taskDescriptionElement);
    }
  }
                                                      
  /**
   * @return the TaskDescriptions
   */
  public Collection<TaskDescription> getTaskDescriptions() {
    return taskDescriptions.values();
  }

  /**
   * @return a unique name for a new task description
   */
  public String genNewTaskName() {
    int suffix = 0;
    while (true) {
      String name = "New Task" + (suffix == 0 ? "" : String.format("(%d)", suffix));
      if (!taskDescriptions.containsKey(name)) return name;
      suffix++;
    }
  }

  /**
   * @param newName
   * @param selectedTaskDescription
   * @return null if successful else the reason the rename could not be performed
   */
  public String renameTaskDescription(String newName, TaskDescription selectedTaskDescription) {
    TaskDescription namedTaskDescription = taskDescriptions.get(newName);
    if (namedTaskDescription != null && namedTaskDescription != selectedTaskDescription) {
      return String.format("Another task description named %s already exists", newName);
    }
    taskDescriptions.remove(selectedTaskDescription.getName());
    selectedTaskDescription.setName(newName);
    taskDescriptions.put(newName, selectedTaskDescription);
    return null;
  }

  /**
   * @param taskDescription
   */
  public void addTaskDescription(TaskDescription taskDescription) {
    taskDescriptions.put(taskDescription.getName(), taskDescription);
    setModified(true);
  }

  /**
   * @param taskName
   * @return the named TaskDescription
   */
  public TaskDescription getTaskDescription(String taskName) {
    return taskDescriptions.get(taskName);
  }
}
