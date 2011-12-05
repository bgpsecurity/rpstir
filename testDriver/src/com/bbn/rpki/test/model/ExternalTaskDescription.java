/*
 * Created on Nov 22, 2011
 */
package com.bbn.rpki.test.model;

import java.io.File;

import org.jdom.Element;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class ExternalTaskDescription extends TaskDescription {

  private static final String TAG_SCRIPT_FILE = "script-file";
  
  private File scriptFile;

  /**
   * @param element
   */
  public ExternalTaskDescription(Element element) {
    super(element);
    this.scriptFile = new File(element.getChildText(TAG_SCRIPT_FILE));
  }

  /**
   * @param name
   * @param description
   */
  public ExternalTaskDescription(String name, String description) {
    super(name, description);
  }

  /**
   * @see com.bbn.rpki.test.model.TaskDescription#toXML(org.jdom.Element)
   */
  @Override
  public void toXML(Element element) {
    super.toXML(element);
    Element scriptFileElement = new Element(TAG_SCRIPT_FILE);
    scriptFileElement.setText(scriptFile.toString());
    element.addContent(scriptFileElement);
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

}
