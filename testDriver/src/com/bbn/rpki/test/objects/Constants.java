/*
 * Created on Nov 14, 2011
 */
package com.bbn.rpki.test.objects;

import java.math.BigInteger;

/**
 * <Enter the description of this type here>
 *
 * @author RTomlinson
 */
public interface Constants {
  /** RPKI_HOME environment variable */
  public static final String RPKI_ROOT = System.getenv("RPKI_ROOT");

  /** Path to the objects directory */
  public static final String OBJECT_PATH = RPKI_ROOT + "/testbed/javaObjects/";

  /** Path to the repository directory */
  public static final String REPO_PATH = OBJECT_PATH + "REPOSITORY/";

  /** Path to the configs directory */
  public static final String CONFIG_PATH = OBJECT_PATH + "configs/";

  /** Path to the keys directory */
  public static final String KEYS_PATH = OBJECT_PATH + "keys/";

  /** Debugging enabled */
  public static final boolean DEBUG_ON = true;

  /** Prefix for rsync URL */
  public static final String RSYNC_EXTENSION = "r:rsync://";

  /** Generally useful 16-bit mask */
  public static final BigInteger SXTN_BIT_MASK = new BigInteger("ffff", 16);

  /** BigInteger 1 is also useful */
  public static final BigInteger ZERO =  BigInteger.ZERO;

  /** BigInteger 1 is also useful */
  public static final BigInteger ONE =  BigInteger.ONE;

  /** BigInteger 2 is also useful */
  public static final BigInteger TWO = new BigInteger("2");

  /** Location of binaries to be executed */
  public static final String BIN_DIR = ".";
}
