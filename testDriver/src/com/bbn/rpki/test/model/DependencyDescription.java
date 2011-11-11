/*
 * Created on Oct 29, 2011
 */
package com.bbn.rpki.test.model;

import java.util.ArrayList;
import java.util.Collection;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class DependencyDescription {
  private XMLBase successorTaskDescription;
  private final Collection<TaskDescription> predecessorTaskDescriptions = new ArrayList<TaskDescription>();
}
