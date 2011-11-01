/*
 * Created on Oct 30, 2011
 */
package com.bbn.rpki.test.ui;

import javax.swing.JCheckBox;
import javax.swing.JTextField;

import com.bbn.rpki.test.model.ArgDescription;
import com.bbn.rpki.test.model.TestModel;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class ArgDescriptionEditor extends PropertiesEditor {

  private final JTextField argName = new JTextField(40);
  private final JTextField argValue = new JTextField(40);
  private final JCheckBox argIsParameter = new JCheckBox();
  /**
   * @param testModel
   * @param taskDescriptionsEditor
   */
  protected ArgDescriptionEditor(TestModel testModel, TaskDescriptionsEditor taskDescriptionsEditor) {
    super(testModel, taskDescriptionsEditor);
    addToTaskPanel("Arg Name", argName);
    addToTaskPanel("Is Parameter", argIsParameter);
    addToTaskPanel("Arg Value", argValue);
  }
  /**
   * @param argDescription
   */
  public void setArgDescription(ArgDescription argDescription) {
    if (argDescription != null) {
      initTextField(argName, argDescription.getArgName());
      initTextField(argValue, argDescription.getArgValue());
      initBooleanField(argIsParameter, argDescription.isParameter());
    } else {
      initTextField(argName, null);
      initTextField(argValue, null);
      initBooleanField(argIsParameter, null);
    }
  }
}
