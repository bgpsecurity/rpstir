/*
 * Created on Nov 22, 2011
 */
package com.bbn.rpki.test.model;

import org.jdom.Element;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class InternalTaskDescription extends TaskDescription {

  private static final String TAG_CLASS_NAME = "class-name";
  
  private Class<AbstractTask> taskClass;

  /**
   * @param element
   */
  public InternalTaskDescription(Element element) {
    super(element);
    // TODO Auto-generated constructor stub
  }

  /**
   * @param name
   * @param description
   */
  public InternalTaskDescription(String name, String description) {
    super(name, description);
    // TODO Auto-generated constructor stub
  }

}
