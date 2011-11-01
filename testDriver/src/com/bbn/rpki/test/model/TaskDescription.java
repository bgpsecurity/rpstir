/*
 * Created on Oct 29, 2011
 */
package com.bbn.rpki.test.model;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.jdom.Element;

/**
 * Describes a primitive task.
 * 
 * A task is a unit of work. Most tasks are ultimately implemented by executable
 * programs and scripts and have arguments and may produce results. The
 * description of a task include its dependencies, parameters, and results.
 * Some tasks are composed from other tasks and so a task may include a list
 * of its subtasks.
 *
 * @author RTomlinson
 */
public class TaskDescription extends XMLBase {

  private static final String TAG_SCRIPT_FILE = "script-file";
  private static final String TAG_DESCRIPTION = "description";
  private static final String ATTR_NAME = "name";
  private static final String TAG_ARG_DESCRIPTION = "arg-description";
  
  private String name;
  private final String description;
  private File scriptFile;
  private final List<ArgDescription> argDescriptions = new ArrayList<ArgDescription>();
  /**
   * @param name
   * @param description
   */
  public TaskDescription(String name, String description) {
    super();
    this.name = name;
    this.description = description;
  }
  
  /**
   * @param element
   */
  public TaskDescription(Element element) {
    this.name = element.getAttributeValue(ATTR_NAME);
    this.description = element.getChildText(TAG_DESCRIPTION);
    this.scriptFile = new File(element.getChildText(TAG_SCRIPT_FILE));
    List<Element> argDescriptionElements = getChildren(element, TAG_ARG_DESCRIPTION);
    for (Element argDescriptionElement : argDescriptionElements) {
      ArgDescription argDescription = new ArgDescription(argDescriptionElement);
      argDescriptions.add(argDescription);
    }
  }
  
  /**
   * @param element
   */
  public void toXML(Element element) {
    element.setAttribute(ATTR_NAME, name);
    Element descriptionElement = new Element(TAG_DESCRIPTION);
    descriptionElement.setText(description);
    element.addContent(descriptionElement);
    Element scriptFileElement = new Element(TAG_SCRIPT_FILE);
    scriptFileElement.setText(scriptFile.toString());
    element.addContent(scriptFileElement);
    for (ArgDescription argDescription : argDescriptions) {
      Element argDescriptionElement = new Element(TAG_ARG_DESCRIPTION);
      argDescription.toXML(argDescriptionElement);
      element.addContent(argDescriptionElement);
    }
  }
    
  /**
   * @return the name
   */
  public String getName() {
    return name;
  }
  /**
   * @param newName
   */
  public void setName(String newName) {
    name = newName;
  }
  
  /**
   * @return the description
   */
  public String getDescription() {
    return description;
  }
  
  /**
   * @param index
   * @return the specified ArgDescription
   */
  public ArgDescription getArgDescription(int index) {
    return argDescriptions.get(index);
  }
  
  /**
   * @param argDescription
   */
  public void addArgDescription(ArgDescription argDescription) {
    argDescriptions.add(argDescription);
  }
  
  /**
   * @return the scriptFile
   */
  public File getScriptFile() {
    return scriptFile;
  }
  
  /**
   * @param scriptFile
   */
  public void setScriptFile(File scriptFile) {
    this.scriptFile = scriptFile;
  }
  
  /**
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return getName();
  }
  /**
   * @return the number of arg descriptions
   */
  public int getArgDescriptionCount() {
    return argDescriptions.size();
  }

  /**
   * @param index
   */
  public void removeArgDescription(int index) {
    argDescriptions.remove(index);
  }
}
