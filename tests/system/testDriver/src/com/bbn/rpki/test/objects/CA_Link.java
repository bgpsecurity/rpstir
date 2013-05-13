/*
 * Created on Mar 9, 2012
 */
package com.bbn.rpki.test.objects;

/**
 * <Enter the description of this type here>
 *
 * @author tomlinso
 */
public class CA_Link {
  /** the certificate itself */
  public Certificate certificate;
  /** The location (path to) the certificate */
  public String path_CA_cert;
  private String subjKeyFile;

}
