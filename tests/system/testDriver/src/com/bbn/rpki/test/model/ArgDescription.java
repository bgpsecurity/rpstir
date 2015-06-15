/*
 * Created on Oct 30, 2011
 */
package com.bbn.rpki.test.model;

import org.jdom.Element;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public class ArgDescription {

  private static final String ATTR_IS_PARAMETER = "is-parameter";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_NAME = "name";
  private String argName;
  private boolean isParameter;
  private String argValue;
  
  /**
   * Default constructor
   */
  public ArgDescription() {
    // nada
  }
  
  /**
   * Construct from xml
   * @param element
   */
  public ArgDescription(Element element) {
    argName = element.getAttributeValue(ATTR_NAME);
    argValue = element.getAttributeValue(ATTR_VALUE);
    isParameter = Boolean.TRUE.equals(element.getAttribute(ATTR_IS_PARAMETER));
  }
  
  /**
   * @param element the element to configure
   */
  public void toXML(Element element) {
    element.setAttribute(ATTR_NAME, argName);
    element.setAttribute(ATTR_VALUE, argValue);
    element.setAttribute(ATTR_IS_PARAMETER, Boolean.FALSE.toString());
  }
  
  /**
   * @return the argName
   */
  public String getArgName() {
    return argName;
  }
  /**
   * @param argName the argName to set
   */
  public void setArgName(String argName) {
    this.argName = argName;
  }
  /**
   * @return the isParameter
   */
  public boolean isParameter() {
    return isParameter;
  }
  /**
   * @param isParameter the isParameter to set
   */
  public void setParameter(boolean isParameter) {
    this.isParameter = isParameter;
  }
  /**
   * @return the argValue
   */
  public String getArgValue() {
    return argValue;
  }
  /**
   * @param argValue the argValue to set
   */
  public void setArgValue(String argValue) {
    this.argValue = argValue;
  }
}
