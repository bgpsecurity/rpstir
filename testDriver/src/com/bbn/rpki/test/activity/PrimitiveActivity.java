/*
 * Created on Nov 1, 2011
 */
package com.bbn.rpki.test.activity;

import java.util.List;

import com.bbn.rpki.test.model.TaskDescription;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class PrimitiveActivity implements Activity {
  private final TaskDescription taskDescription;
  private final List<ArgBinding> argBindings;
  
  public PrimitiveActivity(TaskDescription taskDescription, List<ArgBinding> argBindings) {
    this.taskDescription = taskDescription;
    this.argBindings = argBindings;
  }
}
