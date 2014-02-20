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
	/**
	 * Path to binaries
	 */
	public static final String buildDir = System.getenv("TESTS_TOP_BUILDDIR");

	/**
	 * Path to source
	 */
	public static final String srcDir = System.getenv("TESTS_TOP_SRCDIR");

	/** Path to the objects directory */
	public static final String OBJECT_PATH = buildDir +
			"/tests/system/testbed/javaObjects/";

	/** Path to the log directory */
	public static final String LOG_DIR = buildDir + "/tests/system/testbed/log";

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

	public static final String RSYNC_LOCAL = buildDir + "/tests/system/testbed/rsync_temp";

	/** Generally useful 16-bit mask */
	public static final BigInteger SXTN_BIT_MASK = new BigInteger("ffff", 16);

	/** BigInteger 2 is useful */
	public static final BigInteger TWO = new BigInteger("2");
}
